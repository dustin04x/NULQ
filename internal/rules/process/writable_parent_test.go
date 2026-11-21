package process

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

// spec describes one synthetic process observation. Defaults model a
// root-owned set-user-ID executable running as root inside a world-writable,
// non-sticky directory on a mount without nosuid/noexec.
type spec struct {
	pid      string
	exePath  string
	exeUID   string
	exeGID   string
	exeMode  string
	setuid   bool
	setgid   bool
	regular  bool
	noExe    bool // omit every executable attribute (kernel thread/unreadable)
	noParent bool // omit every parent-directory attribute
	deleted  bool
	procUID  string
	procEUID string

	parentUID  string
	parentMode string
	sticky     bool
	write      string // acl.Allowed / acl.Denied / acl.Unknown / "" (absent)
	exec       string
	aclStatus  string
	aclAccess  string
	nosuid     string
	noexec     string

	status models.Status
}

func (s spec) observation() models.Observation {
	proc := models.NewObservation(models.KindProcess, "/proc/"+s.pid, "test", time.Now(), nil)
	proc.Status = models.StatusComplete
	if s.status != "" {
		proc.Status = s.status
	}
	proc.Set(models.AttrPID, s.pid)
	proc.Set(models.AttrPPID, "1")
	proc.Set(models.AttrProcessName, "fixture")
	procUID, procEUID := s.procUID, s.procEUID
	if procUID == "" {
		procUID = "1000"
	}
	if procEUID == "" {
		procEUID = "1000"
	}
	proc.Set(models.AttrProcessUID, procUID)
	proc.Set(models.AttrProcessEUID, procEUID)
	proc.Set(models.AttrProcessStartTime, "12345")
	if s.noExe || s.status == models.StatusPartial {
		return proc
	}
	proc.Set(models.AttrExeReadable, "true")
	proc.Set(models.AttrExePath, s.exePath)
	proc.Set(models.AttrExeDeleted, boolString(s.deleted))
	proc.Set(models.AttrExeRegular, boolString(s.regular))
	proc.Set(models.AttrExeUID, s.exeUID)
	proc.Set(models.AttrExeGID, s.exeGID)
	proc.Set(models.AttrExeMode, s.exeMode)
	proc.Set(models.AttrExeSetUID, boolString(s.setuid))
	proc.Set(models.AttrExeSetGID, boolString(s.setgid))
	proc.Set(models.AttrExeNosuid, s.nosuid)
	proc.Set(models.AttrExeNoexec, s.noexec)
	if s.noParent {
		return proc
	}
	proc.Set(models.AttrParentPath, parentOf(s.exePath))
	proc.Set(models.AttrParentUID, s.parentUID)
	proc.Set(models.AttrParentMode, s.parentMode)
	proc.Set(models.AttrParentSticky, boolString(s.sticky))
	if s.write != "" {
		proc.Set(models.AttrParentEffectiveWrite, s.write)
	}
	if s.exec != "" {
		proc.Set(models.AttrParentEffectiveExec, s.exec)
	}
	if s.aclStatus != "" {
		proc.Set(models.AttrParentACLStatus, s.aclStatus)
	}
	if s.aclAccess != "" {
		proc.Set(models.AttrParentACLAccess, s.aclAccess)
	}
	if s.nosuid != "" {
		proc.Set(models.AttrParentNosuid, s.nosuid)
	}
	if s.noexec != "" {
		proc.Set(models.AttrParentNoexec, s.noexec)
	}
	return proc
}

func parentOf(path string) string {
	if index := strings.LastIndex(path, "/"); index > 0 {
		return path[:index]
	}
	return "/"
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// base is a confirmed privileged relationship: root-owned SUID executable
// running as root, in a non-sticky world-writable directory, on a mount
// without nosuid or noexec.
func base() spec {
	return spec{
		pid:        "400",
		exePath:    "/opt/tools/bin/helper",
		exeUID:     "0",
		exeGID:     "0",
		exeMode:    "4755",
		setuid:     true,
		regular:    true,
		procUID:    "0",
		procEUID:   "0",
		parentUID:  "0",
		parentMode: "0777",
		write:      "allowed",
		exec:       "allowed",
		aclStatus:  "present",
		nosuid:     "false",
		noexec:     "false",
	}
}

func evaluate(t *testing.T, observations ...models.Observation) models.RuleResult {
	t.Helper()
	contextObs := models.NewObservation(models.KindExecutionContext, "process:context", "test", time.Now(), nil)
	contextObs.Set(models.AttrEUID, "1000")
	contextObs.Set(models.AttrUID, "1000")
	all := append([]models.Observation{contextObs}, observations...)
	result, err := NewWritableParentRule().Evaluate(context.Background(), store.New(all))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	known := map[string]struct{}{}
	for _, item := range result.Evidence {
		known[item.ID] = struct{}{}
	}
	for _, finding := range result.Findings {
		if err := finding.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if finding.RuleID != "NULQ-PROC-001" {
			t.Fatalf("finding rule = %q", finding.RuleID)
		}
		for _, id := range finding.Evidence {
			if _, ok := known[id]; !ok {
				t.Fatalf("finding %s cites unknown evidence %s", finding.ID, id)
			}
		}
		if len(finding.Limitations) == 0 {
			t.Fatalf("finding %s states no limitations", finding.ID)
		}
		if finding.Remediation == "" || finding.Impact == "" {
			t.Fatalf("finding %s lacks impact or remediation", finding.ID)
		}
	}
	return result
}

func evidenceFields(result models.RuleResult) map[string]bool {
	fields := map[string]bool{}
	for _, item := range result.Evidence {
		if item.Field != "" {
			fields[item.Field] = true
		}
	}
	return fields
}

func TestWritableParentRuleCases(t *testing.T) {
	worldWritableExe := base()
	worldWritableExe.exeMode = "4777"
	worldWritableExe.write = "denied"
	worldWritableExe.parentMode = "0755"

	worldWritableExeUnprivileged := worldWritableExe
	worldWritableExeUnprivileged.procUID = "1000"
	worldWritableExeUnprivileged.procEUID = "1000"

	unknownParent := base()
	unknownParent.write = "unknown"
	unknownParent.exec = "unknown"
	unknownParent.aclStatus = "unreadable"
	unknownParent.aclAccess = ""

	unknownParentUnprivileged := unknownParent
	unknownParentUnprivileged.exeUID = "1000"
	unknownParentUnprivileged.setuid = false
	unknownParentUnprivileged.exeMode = "0755"
	unknownParentUnprivileged.procUID = "1000"
	unknownParentUnprivileged.procEUID = "1000"

	aclGrant := base()
	aclGrant.parentMode = "0755" // mode alone grants nothing to the assessed user
	aclGrant.aclAccess = "u::rwx,u:1000:rwx,g::r-x,m::rwx,o::r-x"

	aclDeny := base()
	aclDeny.aclAccess = "u::rwx,u:1000:r-x,g::r-x,m::r-x,o::rwx"
	aclDeny.write = "denied"
	aclDeny.exec = "allowed"

	aclMasked := base()
	aclMasked.parentMode = "0777"
	aclMasked.aclAccess = "u::rwx,u:1000:rwx,g::r-x,m::r-x,o::r-x"
	aclMasked.write = "denied"

	aclGroup := base()
	aclGroup.parentMode = "0750"
	aclGroup.aclAccess = "u::rwx,g:1001:rwx,g::r-x,m::rwx,o::r-x"

	nosuid := base()
	nosuid.nosuid = "true"

	noexec := base()
	noexec.noexec = "true"

	unknownMount := base()
	unknownMount.nosuid = ""
	unknownMount.noexec = ""

	stickyOther := base()
	stickyOther.parentMode = "1777"
	stickyOther.sticky = true

	stickySelf := base()
	stickySelf.parentUID = "1000"
	stickySelf.parentMode = "1777"
	stickySelf.sticky = true

	unreadable := base()
	unreadable.noExe = true
	unreadable.status = models.StatusUnavailable

	reused := base()
	reused.status = models.StatusPartial

	missingParent := base()
	missingParent.noParent = true

	selfOwned := base()
	selfOwned.exeUID = "1000"
	selfOwned.setuid = false
	selfOwned.exeMode = "0755"
	selfOwned.procUID = "1000"
	selfOwned.procEUID = "1000"

	groupRoot := base()
	groupRoot.setuid = false
	groupRoot.exeMode = "2755"
	groupRoot.setgid = true

	unprivilegedPrivilegedExe := base()
	unprivilegedPrivilegedExe.procUID = "1000"
	unprivilegedPrivilegedExe.procEUID = "1000"

	cases := []struct {
		name       string
		specs      []spec
		wantCount  int
		severity   models.Severity
		confidence models.Confidence
		title      string
		fields     []string
	}{
		{
			name: "protected executable and protected parent", wantCount: 0,
			specs: []spec{func() spec {
				s := base()
				s.parentMode = "0755"
				s.write = "denied"
				return s
			}()},
		},
		{
			name: "writable parent with non-privileged executable", wantCount: 1,
			severity: models.SeverityInfo, confidence: models.ConfidenceMedium,
			title: "Executable consumed by a running process is replaceable by the assessed user",
			fields: []string{
				models.AttrParentEffectiveWrite, models.AttrParentEffectiveExec,
				models.AttrExeUID, models.AttrParentSticky,
			},
			specs: []spec{func() spec {
				s := base()
				s.setuid = false
				s.exeMode = "0755"
				s.procUID = "1000"
				s.procEUID = "1000"
				return s
			}()},
		},
		{
			name: "world-writable privileged executable observed running as root", wantCount: 1,
			severity: models.SeverityHigh, confidence: models.ConfidenceHigh,
			title:  "Running privileged process executes a world-writable root-owned executable",
			fields: []string{models.AttrExeMode, models.AttrExeSetUID, models.AttrProcessEUID, models.AttrPID},
			specs:  []spec{worldWritableExe},
		},
		{
			name: "world-writable privileged executable with no privileged execution", wantCount: 1,
			severity: models.SeverityMedium, confidence: models.ConfidenceMedium,
			title:  "World-writable root-owned privileged executable has no confirmed privileged execution",
			fields: []string{models.AttrExeMode, models.AttrExeSetUID},
			specs:  []spec{worldWritableExeUnprivileged},
		},
		{
			name: "unknown parent permissions for privileged executable", wantCount: 1,
			severity: models.SeverityInfo, confidence: models.ConfidenceLow,
			title: "Replaceability of a privileged executable could not be evaluated",
			fields: []string{
				models.AttrParentEffectiveWrite, models.AttrParentEffectiveExec, models.AttrParentACLStatus,
			},
			specs: []spec{unknownParent},
		},
		{
			name: "unknown parent permissions for unprivileged executable", wantCount: 0,
			specs: []spec{unknownParentUnprivileged},
		},
		{
			name: "ACL grants write on a directory whose mode does not", wantCount: 1,
			severity: models.SeverityHigh, confidence: models.ConfidenceHigh,
			title:  "Running process executes a replaceable root-owned privileged executable",
			fields: []string{models.AttrParentACLStatus, models.AttrParentEffectiveWrite, models.AttrProcessEUID},
			specs:  []spec{aclGrant},
		},
		{
			name: "ACL denies write on a world-writable directory", wantCount: 0,
			specs: []spec{aclDeny},
		},
		{
			name: "named-user ACL entry with a restrictive mask", wantCount: 0,
			specs: []spec{aclMasked},
		},
		{
			name: "supplementary group ACL grant", wantCount: 1,
			severity: models.SeverityHigh, confidence: models.ConfidenceHigh,
			title:  "Running process executes a replaceable root-owned privileged executable",
			fields: []string{models.AttrParentACLStatus, models.AttrParentEffectiveWrite},
			specs:  []spec{aclGroup},
		},
		{
			name: "nosuid mount constrains the relationship", wantCount: 1,
			severity: models.SeverityLow, confidence: models.ConfidenceHigh,
			title:  "Replaceable privileged executable is on a nosuid mount",
			fields: []string{models.AttrParentNosuid},
			specs:  []spec{nosuid},
		},
		{
			name: "noexec mount constrains the relationship", wantCount: 1,
			severity: models.SeverityLow, confidence: models.ConfidenceHigh,
			title:  "Replaceable privileged executable is on a noexec mount",
			fields: []string{models.AttrParentNoexec},
			specs:  []spec{noexec},
		},
		{
			name: "privileged process with unknown mount restriction state", wantCount: 1,
			severity: models.SeverityMedium, confidence: models.ConfidenceMedium,
			title:  "Privileged process runs a replaceable executable with unknown mount restrictions",
			fields: []string{models.AttrProcessEUID},
			specs:  []spec{unknownMount},
		},
		{
			name: "replaceable privileged executable with no privileged execution", wantCount: 1,
			severity: models.SeverityMedium, confidence: models.ConfidenceMedium,
			title:  "Replaceable privileged executable has no observed privileged execution",
			fields: []string{models.AttrExeSetUID, models.AttrParentEffectiveWrite},
			specs:  []spec{unprivilegedPrivilegedExe},
		},
		{
			name: "sticky directory owned by another account protects the entry", wantCount: 0,
			specs: []spec{stickyOther},
		},
		{
			name: "sticky directory owned by the assessed account does not protect entries", wantCount: 1,
			severity: models.SeverityHigh, confidence: models.ConfidenceHigh,
			title:  "Running process executes a replaceable root-owned privileged executable",
			fields: []string{models.AttrParentSticky, models.AttrParentUID},
			specs:  []spec{stickySelf},
		},
		{
			name: "set-group-ID group-root executable is bounded", wantCount: 1,
			severity: models.SeverityMedium, confidence: models.ConfidenceMedium,
			title:  "Replaceable set-group-ID executable grants group-root authority",
			fields: []string{models.AttrExeSetGID, models.AttrExeGID},
			specs:  []spec{groupRoot},
		},
		{
			name: "unreadable executable path produces nothing", wantCount: 0,
			specs: []spec{unreadable, reused},
		},
		{
			name: "parent metadata missing", wantCount: 0,
			specs: []spec{missingParent},
		},
		{
			name: "self-owned unprivileged process is not a boundary crossing", wantCount: 0,
			specs: []spec{selfOwned},
		},
		{
			name: "deleted executable path", wantCount: 0,
			specs: []spec{func() spec {
				s := base()
				s.deleted = true
				return s
			}()},
		},
		{
			name: "kernel thread", wantCount: 0,
			specs: []spec{func() spec {
				s := base()
				s.noExe = true
				return s
			}()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observations := make([]models.Observation, 0, len(tc.specs))
			for _, item := range tc.specs {
				observations = append(observations, item.observation())
			}
			result := evaluate(t, observations...)
			if len(result.Findings) != tc.wantCount {
				t.Fatalf("findings = %d, want %d (%+v)", len(result.Findings), tc.wantCount, result.Findings)
			}
			if tc.wantCount == 0 {
				return
			}
			finding := result.Findings[0]
			if finding.Severity != tc.severity {
				t.Fatalf("severity = %s, want %s", finding.Severity, tc.severity)
			}
			if finding.Confidence != tc.confidence {
				t.Fatalf("confidence = %s, want %s", finding.Confidence, tc.confidence)
			}
			if finding.Title != tc.title {
				t.Fatalf("title = %q, want %q", finding.Title, tc.title)
			}
			if finding.Resource != tc.specs[0].exePath {
				t.Fatalf("resource = %q, want %q", finding.Resource, tc.specs[0].exePath)
			}
			if finding.ResourceKind != models.ResourceFile {
				t.Fatalf("resource kind = %q", finding.ResourceKind)
			}
			fields := evidenceFields(result)
			for _, field := range tc.fields {
				if !fields[field] {
					t.Fatalf("finding cites no evidence for %s (have %v)", field, fields)
				}
			}
		})
	}
}

func TestWritableParentRuleGroupsProcessesByExecutable(t *testing.T) {
	first := base()
	first.pid = "900"
	first.procUID = "1000"
	first.procEUID = "1000"

	second := first
	second.pid = "901"
	second.procEUID = "0"

	third := first
	third.pid = "902"

	result := evaluate(t, first.observation(), second.observation(), third.observation())
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Severity != models.SeverityHigh {
		t.Fatalf("severity = %s, want HIGH from the privileged member", finding.Severity)
	}
	if !strings.Contains(finding.Explanation, "3 observed process(es)") {
		t.Fatalf("explanation does not group the processes: %s", finding.Explanation)
	}
	var sawPID bool
	for _, item := range result.Evidence {
		if item.Field == models.AttrPID && item.ObservedValue == "901" {
			sawPID = true
		}
	}
	if !sawPID {
		t.Fatal("evidence does not cite the privileged PID")
	}
}

func TestWritableParentRuleReportsInconsistentObservations(t *testing.T) {
	first := base()
	first.pid = "700"
	first.nosuid = "false"

	second := base()
	second.pid = "701"
	second.nosuid = "true"

	result := evaluate(t, first.observation(), second.observation())
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Severity != models.SeverityInfo || finding.Confidence != models.ConfidenceLow {
		t.Fatalf("severity/confidence = %s/%s", finding.Severity, finding.Confidence)
	}
	if finding.Title != "Executable path observations are inconsistent across running processes" {
		t.Fatalf("title = %q", finding.Title)
	}
	if !strings.Contains(finding.Explanation, models.AttrParentNosuid) {
		t.Fatalf("explanation does not name the diverging attribute: %s", finding.Explanation)
	}
}

func TestWritableParentRuleRequiresProcessObservations(t *testing.T) {
	meta := NewWritableParentRule().Metadata()
	if len(meta.Required) != 1 || meta.Required[0] != models.KindProcess {
		t.Fatalf("required kinds = %v, want [process]", meta.Required)
	}
	contextObs := models.NewObservation(models.KindExecutionContext, "process:context", "test", time.Now(), nil)
	contextObs.Set(models.AttrEUID, "1000")
	result, err := NewWritableParentRule().Evaluate(context.Background(), store.New([]models.Observation{contextObs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("rule emitted %d findings and %d citations without process observations", len(result.Findings), len(result.Evidence))
	}
}

func TestWritableParentRuleHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	contextObs := models.NewObservation(models.KindExecutionContext, "process:context", "test", time.Now(), nil)
	contextObs.Set(models.AttrEUID, "1000")
	_, err := NewWritableParentRule().Evaluate(ctx, store.New([]models.Observation{contextObs, base().observation()}))
	if err == nil {
		t.Fatal("cancelled context must abort evaluation")
	}
}
