package filesystem

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func boolAttr(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func fileObservation(path string, setuid, setgid bool, ownerUID, owner, group, mode string, writable bool) models.Observation {
	obs := models.NewObservation(models.KindFile, path, "test", time.Now(), nil)
	obs.Set(models.AttrSetUID, boolAttr(setuid))
	obs.Set(models.AttrSetGID, boolAttr(setgid))
	obs.Set(models.AttrOwnerUID, ownerUID)
	obs.Set(models.AttrOwnerUser, owner)
	obs.Set(models.AttrGroupName, group)
	obs.Set(models.AttrMode, mode)
	obs.Set(models.AttrWritableByCurrentUser, boolAttr(writable))
	return obs
}

func directoryObservation(path string, sticky, worldWritable bool, owner, mode string) models.Observation {
	obs := models.NewObservation(models.KindDirectory, path, "test", time.Now(), nil)
	obs.Set(models.AttrSticky, boolAttr(sticky))
	obs.Set(models.AttrWorldWritable, boolAttr(worldWritable))
	obs.Set(models.AttrOwnerUser, owner)
	if owner == "root" {
		obs.Set(models.AttrOwnerUID, "0")
	}
	obs.Set(models.AttrMode, mode)
	obs.Set(models.AttrWritableByCurrentUser, "true")
	return obs
}

func userOwnedStickyDirectory(path, mode, uid string) models.Observation {
	obs := directoryObservation(path, true, true, "tester", mode)
	obs.Set(models.AttrOwnerUID, uid)
	return obs
}

func pathEntryObservation(resource string, index int, entry string, exists, isDir, writable bool, ownerUID, owner string) models.Observation {
	obs := models.NewObservation(models.KindPathEntry, resource, "test", time.Now(), nil)
	obs.Set(models.AttrPathIndex, itoa(index))
	obs.Set(models.AttrPathEntry, entry)
	obs.Set(models.AttrPathExists, boolAttr(exists))
	obs.Set(models.AttrIsDirectory, boolAttr(isDir))
	obs.Set(models.AttrWritableByCurrentUser, boolAttr(writable))
	obs.Set(models.AttrOwnerUID, ownerUID)
	obs.Set(models.AttrOwnerUser, owner)
	obs.Set(models.AttrMode, "0755")
	return obs
}

func executionContext(euid string) models.Observation {
	obs := models.NewObservation(models.KindExecutionContext, "process:1", "test", time.Now(), nil)
	obs.Set(models.AttrEUID, euid)
	obs.Set(models.AttrUID, euid)
	obs.Set(models.AttrUsername, "tester")
	return obs
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

func TestSUIDRuleSeverityIsContextual(t *testing.T) {
	contextObs := executionContext("1000")
	cases := []struct {
		name        string
		observation models.Observation
		want        models.Severity
		title       string
	}{
		{"standard root-owned inventory", fileObservation("/usr/bin/passwd", true, false, "0", "root", "root", "4755", false), models.SeverityInfo, "Set-owner-ID executable inventory"},
		{"non-standard path", fileObservation("/opt/vendor/helper", true, false, "0", "root", "root", "4755", false), models.SeverityLow, "Privileged executable outside standard system directories"},
		{"root-owned, writable by user", fileObservation("/usr/bin/local-tool", true, false, "0", "root", "root", "4755", true), models.SeverityHigh, "Root-owned privileged executable is writable by the current user"},
		{"non-root owner, not writable", fileObservation("/usr/local/bin/tool", true, false, "1001", "other", "other", "4755", false), models.SeverityLow, "Set-user-ID executable is owned by a non-root account"},
		{"writable, other owner", fileObservation("/usr/local/bin/tool", true, false, "1001", "other", "other", "4755", true), models.SeverityMedium, "Privileged executable owned by another account is writable"},
		{"writable, self-owned", fileObservation("/home/tester/bin/tool", true, false, "1000", "tester", "tester", "4755", true), models.SeverityLow, "Privileged executable is owned and writable by the current user"},
		{"setgid in standard path", fileObservation("/usr/bin/wall", false, true, "0", "root", "tty", "2755", false), models.SeverityInfo, "Set-owner-ID executable inventory"},
		{"non-executable root-owned SUID", fileObservation("/opt/data/notes", true, false, "0", "root", "root", "4644", true), models.SeverityInfo, "Set-owner-ID bit on a non-executable file is inert"},
	}

	rule := NewSUIDRule()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rule.Evaluate(context.Background(), store.New([]models.Observation{contextObs, tc.observation}))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != 1 {
				t.Fatalf("want 1 finding, got %d", len(result.Findings))
			}
			if got := result.Findings[0].Severity; got != tc.want {
				t.Fatalf("severity = %s, want %s", got, tc.want)
			}
			if got := result.Findings[0].Title; got != tc.title {
				t.Fatalf("title = %q, want %q", got, tc.title)
			}
			if err := result.Findings[0].Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSUIDRuleIgnoresOrdinaryFiles(t *testing.T) {
	ordinary := fileObservation("/usr/bin/ls", false, false, "0", "root", "root", "0755", false)
	result, err := NewSUIDRule().Evaluate(context.Background(), store.New([]models.Observation{ordinary}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("ordinary files must not produce findings: %+v", result.Findings)
	}
}

func TestWorldWritableRuleIsContextual(t *testing.T) {
	cases := []struct {
		name         string
		directories  []models.Observation
		files        []models.Observation
		paths        []models.Observation
		wantCount    int
		wantSeverity models.Severity
	}{
		{
			name:        "sticky directory is normal",
			directories: []models.Observation{directoryObservation("/tmp", true, true, "root", "1777")},
			wantCount:   0,
		},
		{
			name:         "non-sticky directory",
			directories:  []models.Observation{directoryObservation("/var/shared", false, true, "root", "0777")},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		},
		{
			name:         "PATH membership alone does not escalate",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			paths:        []models.Observation{pathEntryObservation("/opt/bin", 0, "/opt/bin", true, true, true, "0", "root")},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		},
		{
			name:         "direct child privileged executable escalates",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			files:        []models.Observation{fileObservation("/opt/bin/tool", true, false, "0", "root", "root", "4755", false)},
			wantCount:    1,
			wantSeverity: models.SeverityHigh,
		}, {
			name:         "nested privileged executable does not escalate",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			files:        []models.Observation{fileObservation("/opt/bin/inner/tool", true, false, "0", "root", "root", "4755", false)},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		}, {
			name:         "non-executable SUID file does not escalate",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			files:        []models.Observation{fileObservation("/opt/bin/notes", true, false, "0", "root", "root", "4644", false)},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		},
		{
			name:         "user-owned SUID child does not escalate",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			files:        []models.Observation{fileObservation("/opt/bin/user-tool", true, false, "1001", "other", "other", "4755", false)},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		},
		{
			name:         "root-owned SGID child does not escalate to root",
			directories:  []models.Observation{directoryObservation("/opt/bin", false, true, "root", "0777")},
			files:        []models.Observation{fileObservation("/opt/bin/group-tool", false, true, "0", "root", "wheel", "2755", false)},
			wantCount:    1,
			wantSeverity: models.SeverityMedium,
		},
		{
			name:        "root-owned sticky directory protects entries",
			directories: []models.Observation{directoryObservation("/var/shared", true, true, "root", "1777")},
			files:       []models.Observation{fileObservation("/var/shared/tool", true, false, "0", "root", "root", "4755", false)},
			wantCount:   0,
		},
		{
			name:         "user-owned sticky directory does not protect entries",
			directories:  []models.Observation{userOwnedStickyDirectory("/home/tester/shared", "1777", "1000")},
			files:        []models.Observation{fileObservation("/home/tester/shared/tool", true, false, "0", "root", "root", "4755", false)},
			wantCount:    1,
			wantSeverity: models.SeverityHigh,
		},
	}

	rule := NewWorldWritableRule()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observations := append([]models.Observation{}, tc.directories...)
			observations = append(observations, tc.files...)
			observations = append(observations, tc.paths...)
			observations = append(observations, executionContext("1000"))
			result, err := rule.Evaluate(context.Background(), store.New(observations))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.wantCount {
				t.Fatalf("want %d findings, got %d", tc.wantCount, len(result.Findings))
			}
			if tc.wantCount > 0 && result.Findings[0].Severity != tc.wantSeverity {
				t.Fatalf("severity = %s, want %s", result.Findings[0].Severity, tc.wantSeverity)
			}
		})
	}
}

func TestWorldWritableRuleCitesReplaceableExecutable(t *testing.T) {
	directory := directoryObservation("/opt/bin", false, true, "root", "0777")
	file := fileObservation("/opt/bin/tool", true, false, "0", "root", "root", "4755", false)
	result, err := NewWorldWritableRule().Evaluate(context.Background(), store.New([]models.Observation{directory, file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if len(result.Findings[0].Evidence) < 8 {
		t.Fatalf("finding must cite the directory and the replaceable executable, got %d evidence items", len(result.Findings[0].Evidence))
	}
}

// TestMountFlagsRuleIsContextual pins the two reported mount-flag
// relationships and their negative controls. Mount flags constrain execution
// semantics; they are never reported as escalation by themselves.
func TestMountFlagsRuleIsContextual(t *testing.T) {
	suidOnNosuid := fileObservation("/mnt/nosuid/tool", true, false, "0", "root", "root", "4755", false)
	suidOnNosuid.Set(models.AttrNosuid, "true")
	suidOnNosuid.Set(models.AttrMountPoint, "/mnt/nosuid")

	suidOnExec := fileObservation("/mnt/exec/tool", true, false, "0", "root", "root", "4755", false)
	suidOnExec.Set(models.AttrNosuid, "false")
	suidOnExec.Set(models.AttrMountPoint, "/mnt/exec")

	worldWritableNoexec := directoryObservation("/mnt/ro-shared", false, true, "root", "0777")
	worldWritableNoexec.Set(models.AttrNoexec, "true")
	worldWritableNoexec.Set(models.AttrMountPoint, "/mnt/ro-shared")

	worldWritableExec := directoryObservation("/mnt/rw-shared", false, true, "root", "0777")
	worldWritableExec.Set(models.AttrNoexec, "false")
	worldWritableExec.Set(models.AttrMountPoint, "/mnt/rw-shared")

	cases := []struct {
		name         string
		observation  models.Observation
		wantFindings int
		wantSeverity models.Severity
	}{
		{"set-owner-ID executable on nosuid mount", suidOnNosuid, 1, models.SeverityInfo},
		{"set-owner-ID executable on mount without nosuid", suidOnExec, 0, ""},
		{"world-writable directory on noexec mount", worldWritableNoexec, 1, models.SeverityInfo},
		{"world-writable directory on mount without noexec", worldWritableExec, 0, ""},
	}

	rule := NewMountFlagsRule()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rule.Evaluate(context.Background(), store.New([]models.Observation{tc.observation}))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.wantFindings {
				t.Fatalf("want %d findings, got %d", tc.wantFindings, len(result.Findings))
			}
			if tc.wantFindings == 0 {
				return
			}
			finding := result.Findings[0]
			if finding.Severity != tc.wantSeverity {
				t.Fatalf("severity = %s, want %s", finding.Severity, tc.wantSeverity)
			}
			if err := finding.Validate(); err != nil {
				t.Fatal(err)
			}
			if len(finding.Evidence) == 0 {
				t.Fatal("mount-flag finding must cite evidence")
			}
		})
	}
}

// TestEffectiveWritableNormalization pins the three-way decision and the
// M1.5 compatibility fallback. Missing evidence must stay unknown, never denied,
// and a conflicting legacy boolean must not override a precise attribute.
func TestEffectiveWritableNormalization(t *testing.T) {
	caseWith := func(effective, legacy string) models.Observation {
		obs := models.NewObservation(models.KindDirectory, "/x", "test", time.Now(), nil)
		if effective != "" {
			obs.Set(models.AttrEffectiveWrite, effective)
		}
		if legacy != "" {
			obs.Set(models.AttrWritableByCurrentUser, legacy)
		}
		return obs
	}
	cases := []struct {
		name         string
		observation  models.Observation
		wantDecision string
		wantKnown    bool
	}{
		{"precise allowed", caseWith("allowed", ""), "allowed", true},
		{"precise denied", caseWith("denied", ""), "denied", true},
		{"precise unknown", caseWith("unknown", ""), "unknown", true},
		{"precise wins over conflicting legacy", caseWith("denied", "true"), "denied", true},
		{"legacy true", caseWith("", "true"), "allowed", true},
		{"legacy false", caseWith("", "false"), "denied", true},
		{"no evidence stays unknown", caseWith("", ""), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, known := effectiveWritable(tc.observation)
			if decision != tc.wantDecision || known != tc.wantKnown {
				t.Fatalf("effectiveWritable = (%q, %v), want (%q, %v)", decision, known, tc.wantDecision, tc.wantKnown)
			}
		})
	}
}

func TestPathEntryRuleCases(t *testing.T) {
	contextObs := executionContext("1000")
	cases := []struct {
		name         string
		entry        models.Observation
		wantFindings int
		wantSeverity models.Severity
	}{
		{
			name:         "empty entry",
			entry:        pathEntryObservation("<PATH index 2: empty>", 2, "", false, false, false, "", ""),
			wantFindings: 1,
			wantSeverity: models.SeverityLow,
		},
		{
			name:         "relative entry",
			entry:        pathEntryObservation("bin", 1, "bin", true, true, false, "1000", "tester"),
			wantFindings: 1,
			wantSeverity: models.SeverityLow,
		},
		{
			name:         "writable and root-owned",
			entry:        pathEntryObservation("/usr/local/sbin", 0, "/usr/local/sbin", true, true, true, "0", "root"),
			wantFindings: 1,
			wantSeverity: models.SeverityLow,
		},
		{
			name:         "writable and self-owned",
			entry:        pathEntryObservation("/home/tester/bin", 0, "/home/tester/bin", true, true, true, "1000", "tester"),
			wantFindings: 1,
			wantSeverity: models.SeverityLow,
		},
		{
			name:         "not writable",
			entry:        pathEntryObservation("/usr/bin", 0, "/usr/bin", true, true, false, "0", "root"),
			wantFindings: 0,
		},
		{
			name:         "user-owned but not writable",
			entry:        pathEntryObservation("/home/tester/readonly", 0, "/home/tester/readonly", true, true, false, "1000", "tester"),
			wantFindings: 0,
		},
		{
			name:         "missing entry",
			entry:        pathEntryObservation("/opt/absent", 0, "/opt/absent", false, false, false, "", ""),
			wantFindings: 0,
		},
	}

	rule := NewPathEntryRule()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rule.Evaluate(context.Background(), store.New([]models.Observation{contextObs, tc.entry}))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.wantFindings {
				t.Fatalf("want %d findings, got %d", tc.wantFindings, len(result.Findings))
			}
			if tc.wantFindings > 0 {
				if got := result.Findings[0].Severity; got != tc.wantSeverity {
					t.Fatalf("severity = %s, want %s", got, tc.wantSeverity)
				}
			}
		})
	}
}
