// Package process implements detection over process observations.
//
// Rules in this package consume normalized process observations produced by
// the linux.process collector. They never read /proc themselves, never execute
// a discovered binary and never infer privilege from a path name.
package process

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
	"github.com/dustin04x/nulq/internal/platform/linux/acl"
)

type writableParentRule struct{}

// NewWritableParentRule builds the process-aware writable-parent rule.
//
// Detection contract (attributes consumed):
//
//	process:  pid, comm, process_uid, process_euid, start_time
//	executable: exe_path, exe_deleted, exe_readable, exe_regular, exe_uid,
//	            exe_mode, exe_setuid, exe_setgid, exe_mount_point,
//	            exe_nosuid, exe_noexec
//	parent:   parent_path, parent_uid, parent_mode, parent_sticky,
//	            parent_effective_write, parent_effective_exec,
//	            parent_acl_status, parent_mount_point, parent_nosuid,
//	            parent_noexec
//
// and, for the assessed identity, the execution-context euid.
//
// Required evidence per outcome:
//
//	inventory        no finding; the process observation is the record.
//	exposure         INFO: replaceable parent + an authority boundary other
//	                 than the assessed user (other-owned executable, another
//	                 process identity, or a set-user/group-ID bit).
//	potential impact MEDIUM: replaceable parent + root-owned SUID executable
//	                 but no observed privileged execution, or mount state that
//	                 prevents confirming escalation semantics.
//	confirmed        HIGH: all of the above plus an observed process running
//	                 that executable with euid 0, on a mount observed without
//	                 nosuid/noexec.
//
// Unknown permission, ACL or mount state never produces a replaceability
// claim; it produces at most an INFO finding that says the relationship could
// not be evaluated.
func NewWritableParentRule() interfaces.Rule { return writableParentRule{} }

func (r writableParentRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-PROC-001",
		Version:     "1.0.0",
		Name:        "Executable consumed by a running process is replaceable in its parent directory",
		Description: "A running process executes an executable path whose containing directory the assessed user can modify, so the file consumed by that process can be replaced by name.",
		Category:    "permissions",
		Module:      "process",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindProcess},
		Platforms:   []string{"linux"},
	}
}

// group is every process observed running one executable path.
type group struct {
	exePath           string
	members           []models.Observation
	privilegedRuntime bool
	privilegedPID     string
}

func (r writableParentRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	assessed, haveAssessed := parseUID(executionEUID(obs))

	groups := map[string]*group{}
	var paths []string
	for _, proc := range obs.ByKind(models.KindProcess) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		// An unavailable or failed observation establishes no identity.
		if proc.Status != models.StatusComplete && proc.Status != models.StatusPartial {
			continue
		}
		exePath, ok := proc.Attr(models.AttrExePath)
		if !ok || exePath == "" {
			// Kernel thread, or the executable path could not be read.
			continue
		}
		if proc.Bool(models.AttrExeDeleted) {
			// The directory entry is gone: replacing it is not the same
			// relationship as replacing a path a future execution will use.
			continue
		}
		if !proc.Bool(models.AttrExeRegular) {
			continue
		}
		if _, ok := proc.Attr(models.AttrParentPath); !ok {
			continue
		}
		current, seen := groups[exePath]
		if !seen {
			current = &group{exePath: exePath}
			groups[exePath] = current
			paths = append(paths, exePath)
		}
		current.members = append(current.members, proc)
		if euid, ok := parseUID(attr(proc, models.AttrProcessEUID)); ok && euid == 0 {
			current.privilegedRuntime = true
			if current.privilegedPID == "" {
				current.privilegedPID = attr(proc, models.AttrPID)
			}
		}
	}
	sort.Strings(paths)

	var findings []models.Finding
	for _, exePath := range paths {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		current := groups[exePath]
		sort.SliceStable(current.members, func(i, j int) bool {
			left, leftOK := parseUID(attr(current.members[i], models.AttrPID))
			right, rightOK := parseUID(attr(current.members[j], models.AttrPID))
			if leftOK && rightOK {
				return left < right
			}
			return current.members[i].Resource < current.members[j].Resource
		})
		first := current.members[0]

		// Divergent observations of one path cannot support a relationship
		// claim; report the inconsistency instead of guessing.
		if field := firstInconsistency(current.members); field != "" {
			finding := models.NewFinding(meta, exePath, models.ResourceFile,
				models.SeverityInfo, models.ConfidenceLow,
				"Executable path observations are inconsistent across running processes", now)
			finding.Explanation = fmt.Sprintf(
				"Processes running %s reported different values for %s. NULQ does not assert a replaceability relationship when the executable metadata disagrees between observations.",
				exePath, field)
			finding.Impact = "No permission conclusion is drawn. The path may be a bind mount, a renamed directory, or the observations may have been taken while the path was changing."
			finding.Remediation = "Re-run the scan when the path is stable, and verify whether the executable is bind-mounted or replaced concurrently by a package manager or deployment tool."
			finding.Limitations = []string{
				"Only the diverging attribute is reported; the full attribute sets are in the observations.",
				"Execution of the executable is not observed.",
			}
			finding.AddEvidence(
				builder.Add(first, models.AttrExePath, "Executable path whose observations disagree."),
				builder.Add(first, field, "First observed value; later processes reported a different one."),
			)
			findings = append(findings, finding)
			continue
		}

		privilegedExe := privilegedExecutable(first)
		groupRootExe := !privilegedExe && groupRootExecutable(first)

		// A world-writable privileged executable is directly modifiable, which
		// is independent of whether its directory entry is replaceable.
		if privilegedExe && executableWorldWritable(first) {
			severity, confidence := models.SeverityMedium, models.ConfidenceMedium
			title := "World-writable root-owned privileged executable has no confirmed privileged execution"
			impact := "Any local account can overwrite the executable's contents. No process running it with elevated authority was observed, so the privileged impact is potential rather than confirmed."
			switch {
			case mountFlag(first, models.AttrParentNoexec, models.AttrExeNoexec) == "true" ||
				mountFlag(first, models.AttrParentNosuid, models.AttrExeNosuid) == "true":
				severity, confidence = models.SeverityLow, models.ConfidenceHigh
				title = "World-writable privileged executable is on a mount that constrains privileged execution"
				impact = "Any local account can overwrite the executable, but nosuid or noexec on its mount prevents the replaced content from gaining the executable owner's authority. This is a path-integrity exposure."
			case current.privilegedRuntime &&
				mountFlag(first, models.AttrParentNosuid, models.AttrExeNosuid) == "false" &&
				mountFlag(first, models.AttrParentNoexec, models.AttrExeNoexec) == "false":
				severity, confidence = models.SeverityHigh, models.ConfidenceHigh
				title = "Running privileged process executes a world-writable root-owned executable"
				impact = "Any local account can overwrite this executable, and it is observed running with effective UID 0 on a mount without nosuid, so overwriting it yields attacker-controlled code with root authority on the next execution."
			}
			finding := models.NewFinding(meta, exePath, models.ResourceFile, severity, confidence, title, now)
			finding.Explanation = fmt.Sprintf(
				"%s (mode %s, owner %s) grants other-write and carries the set-user-ID bit, so its contents can be modified without touching its directory entry.",
				exePath, attr(first, models.AttrExeMode), attr(first, models.AttrExeUID))
			finding.Impact = impact
			finding.Remediation = "Remove world-write permission from privileged executables and keep them owned by root with mode 0755. Monitor the file's integrity independently of its directory permissions."
			finding.Limitations = []string{
				"Only mode bits of the executable are evaluated; an ACL that grants write to another identity is not collected for the executable file itself.",
				"No file was modified and no execution was attempted.",
				"Process environments, command lines and descriptors are never read.",
			}
			finding.AddEvidence(
				builder.Add(first, models.AttrExePath, "Executable path observed for the running process."),
				builder.Add(first, models.AttrExeMode, "Executable mode bits including the other-write permission."),
				builder.Add(first, models.AttrExeUID, "Executable owner."),
				builder.Add(first, models.AttrExeSetUID, "Set-user-ID bit."),
				builder.Add(first, models.AttrParentNosuid, "Mount nosuid flag for the containing directory."),
				builder.Add(first, models.AttrParentNoexec, "Mount noexec flag for the containing directory."),
			)
			if current.privilegedRuntime {
				finding.AddEvidence(
					builder.Add(first, models.AttrProcessEUID, "Observed effective UID of the process consuming the executable."),
					builder.Add(first, models.AttrPID, "Process observed running the executable with that authority."),
				)
			}
			findings = append(findings, finding)
			continue
		}

		replace, replaceReason := replaceability(first, assessed, haveAssessed)

		if replace != acl.Allowed {
			if privilegedExe && replace == acl.Unknown {
				finding := models.NewFinding(meta, exePath, models.ResourceFile,
					models.SeverityInfo, models.ConfidenceLow,
					"Replaceability of a privileged executable could not be evaluated", now)
				finding.Explanation = fmt.Sprintf(
					"%s is a root-owned executable carrying the set-user-ID bit, but %s. NULQ does not claim that the path is replaceable.",
					exePath, replaceReason)
				finding.Impact = "No exposure is claimed. Replaceability by the assessed user is unknown, so a privilege-boundary weakness can be neither confirmed nor excluded."
				finding.Remediation = "Re-run the scan with an identity that can read the containing directory's metadata and ACL, or inspect the directory permissions manually."
				finding.Limitations = []string{
					"Unknown permission or ACL state is reported as unknown, never as allowed.",
					"Execution of the executable is not observed.",
				}
				finding.AddEvidence(
					builder.Add(first, models.AttrExePath, "Executable path that could not be evaluated."),
					builder.Add(first, models.AttrExeSetUID, "Set-user-ID bit that makes the executable privileged."),
					builder.Add(first, models.AttrParentEffectiveWrite, "Effective write permission for the assessed identity."),
					builder.Add(first, models.AttrParentEffectiveExec, "Effective directory search permission for the assessed identity."),
					builder.Add(first, models.AttrParentACLStatus, "ACL state used for the effective permission evaluation."),
				)
				findings = append(findings, finding)
			}
			continue
		}

		severity, confidence, title := models.SeverityMedium, models.ConfidenceMedium, ""
		impact := ""
		switch {
		case privilegedExe && mountFlag(first, models.AttrParentNoexec, models.AttrExeNoexec) == "true":
			severity, confidence = models.SeverityLow, models.ConfidenceHigh
			title = "Replaceable privileged executable is on a noexec mount"
			impact = "The directory entry can be replaced, but noexec prevents the replaced file from being executed directly from that mount. The relationship is a path-integrity exposure, not confirmed privilege escalation."
		case privilegedExe && mountFlag(first, models.AttrParentNosuid, models.AttrExeNosuid) == "true":
			severity, confidence = models.SeverityLow, models.ConfidenceHigh
			title = "Replaceable privileged executable is on a nosuid mount"
			impact = "The directory entry can be replaced, but nosuid prevents the set-user-ID bit from granting its usual authority on that mount. The relationship is a path-integrity exposure, not confirmed privilege escalation."
		case privilegedExe && current.privilegedRuntime &&
			mountFlag(first, models.AttrParentNosuid, models.AttrExeNosuid) == "false" &&
			mountFlag(first, models.AttrParentNoexec, models.AttrExeNoexec) == "false":
			severity, confidence = models.SeverityHigh, models.ConfidenceHigh
			title = "Running process executes a replaceable root-owned privileged executable"
			impact = fmt.Sprintf(
				"Process %s is observed running this executable with effective UID 0. Because the assessed user can replace the executable in its containing directory on a mount without nosuid, the next privileged execution of that path can be made to run attacker-controlled code with root authority.",
				current.privilegedPID)
		case privilegedExe && current.privilegedRuntime:
			severity, confidence = models.SeverityMedium, models.ConfidenceMedium
			title = "Privileged process runs a replaceable executable with unknown mount restrictions"
			impact = "A process is observed running this executable with effective UID 0, and the executable is replaceable. Mount nosuid/noexec state for the executable path is not fully observed, so escalation semantics on that mount cannot be confirmed or excluded."
		case privilegedExe:
			severity, confidence = models.SeverityMedium, models.ConfidenceMedium
			title = "Replaceable privileged executable has no observed privileged execution"
			impact = "The executable is root-owned, carries the set-user-ID bit, and is replaceable by the assessed user on a mount where SUID semantics appear to apply. No process running it with elevated authority was observed, so this is a potential privilege impact rather than a confirmed one."
		case groupRootExe:
			severity, confidence = models.SeverityMedium, models.ConfidenceMedium
			title = "Replaceable set-group-ID executable grants group-root authority"
			impact = "Replacing the executable would let the attacker control code executed with the authority of group root. This does not grant user root, so it is a bounded privilege impact."
		case boundaryCrossed(first, assessed, haveAssessed):
			severity, confidence = models.SeverityInfo, models.ConfidenceMedium
			title = "Executable consumed by a running process is replaceable by the assessed user"
			impact = "The affected process or another account relies on the integrity of this executable path. Replacement influences code executed under that account's authority; no privileged boundary crossing was observed."
		default:
			// Self-owned, unprivileged executable with no SUID/SGID bit: the
			// assessed user can already modify their own code, so this is not
			// a permission boundary crossing and is deliberately silent.
			continue
		}

		finding := models.NewFinding(meta, exePath, models.ResourceFile, severity, confidence, title, now)
		finding.Explanation = fmt.Sprintf(
			"%s (mode %s, owner %s) is executed by %d observed process(es) and its containing directory %s (mode %s) is modifiable by the assessed identity: %s.",
			exePath, attr(first, models.AttrExeMode), attr(first, models.AttrExeUID),
			len(current.members), attr(first, models.AttrParentPath), attr(first, models.AttrParentMode), replaceReason)
		finding.Impact = impact
		finding.Remediation = "Move privileged executables out of user-writable directories and remove write access to the containing directory, or set the sticky bit with a trusted owner. Replacing the path is prevented by directory permissions, not by file mode bits."
		finding.Limitations = []string{
			"No file was replaced and no execution was attempted; replaceability is derived from effective permissions and the sticky-bit rules.",
			"Only the executable path and its immediate containing directory are evaluated; other writable ancestors and interpreter chain components are not.",
			"Process environments, command lines, memory, descriptors and parent lineage beyond the numeric PPID are never read.",
			"When ACL state is malformed or unreadable the relationship is reported as unknown, not as allowed.",
			"Processes sharing one executable are reported once, with the affected PIDs grouped in the explanation.",
		}
		if current.privilegedRuntime && severity != models.SeverityHigh {
			finding.Limitations = append(finding.Limitations,
				"A privileged execution of this path was observed, but mount or ACL state prevented confirming the escalation semantics.")
		}
		finding.AddEvidence(
			builder.Add(first, models.AttrExePath, "Executable path consumed by the observed process."),
			builder.Add(first, models.AttrExeUID, "Owner of the executable; root ownership is required for root authority."),
			builder.Add(first, models.AttrExeMode, "Executable permission bits."),
			builder.Add(first, models.AttrExeSetUID, "Set-user-ID bit."),
			builder.Add(first, models.AttrExeSetGID, "Set-group-ID bit."),
			builder.Add(first, models.AttrExeGID, "Executable group, compared with group root."),
			builder.Add(first, models.AttrParentPath, "Immediate containing directory."),
			builder.Add(first, models.AttrParentUID, "Containing directory owner, used for sticky-bit entry protection."),
			builder.Add(first, models.AttrParentMode, "Containing directory permission bits."),
			builder.Add(first, models.AttrParentEffectiveWrite, "Effective write permission for the assessed identity."),
			builder.Add(first, models.AttrParentEffectiveExec, "Effective directory search permission for the assessed identity."),
			builder.Add(first, models.AttrParentSticky, "Sticky bit controlling entry protection."),
			builder.Add(first, models.AttrParentACLStatus, "ACL state used for effective permissions."),
			builder.Add(first, models.AttrParentNosuid, "Mount nosuid flag for the containing directory."),
			builder.Add(first, models.AttrParentNoexec, "Mount noexec flag for the containing directory."),
		)
		if current.privilegedRuntime {
			privileged := first
			for _, member := range current.members {
				if attr(member, models.AttrProcessEUID) == "0" {
					privileged = member
					break
				}
			}
			finding.AddEvidence(
				builder.Add(privileged, models.AttrProcessEUID, "Observed effective UID of the privileged process."),
				builder.Add(privileged, models.AttrPID, "Process observed running the executable with that authority."),
			)
		}
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// replaceability decides whether the assessed identity can replace the
// executable's directory entry, and explains the decision in one clause.
func replaceability(exe models.Observation, assessed uint32, haveAssessed bool) (acl.Access, string) {
	write := accessValue(attr(exe, models.AttrParentEffectiveWrite))
	exec := accessValue(attr(exe, models.AttrParentEffectiveExec))
	sticky := exe.Bool(models.AttrParentSticky)
	parentOwner, haveParentOwner := parseUID(attr(exe, models.AttrParentUID))
	exeOwner, haveExeOwner := parseUID(attr(exe, models.AttrExeUID))

	switch aclStatus := attr(exe, models.AttrParentACLStatus); aclStatus {
	case "malformed", "unreadable", "unsupported":
		// A known-unusable ACL makes effective permissions unknown even if
		// mode bits would otherwise suggest write access.
		if write != acl.Denied {
			return acl.Unknown, "the containing directory's ACL state is " + aclStatus +
				", so effective access is unknown"
		}
	}

	switch {
	case write == acl.Unknown:
		return acl.Unknown, "effective write permission on the containing directory is unknown"
	case write != acl.Allowed:
		return acl.Denied, "the assessed identity has no write permission on the containing directory"
	case exec == acl.Unknown:
		return acl.Unknown, "effective search permission on the containing directory is unknown"
	case exec != acl.Allowed:
		return acl.Denied, "the assessed identity cannot search the containing directory"
	}
	if sticky && haveAssessed && haveParentOwner && haveExeOwner && assessed != 0 &&
		parentOwner != assessed && exeOwner != assessed {
		return acl.Denied, "the sticky bit on a directory owned by another account protects the entry"
	}
	if sticky && (!haveAssessed || !haveParentOwner || !haveExeOwner) {
		return acl.Unknown, "the sticky bit is set and ownership could not be compared, so entry protection is unknown"
	}
	return acl.Allowed, fmt.Sprintf(
		"effective write and search permissions are granted (write=%s, exec=%s, sticky=%t)",
		write, exec, sticky)
}

// boundaryCrossed reports whether the executable's integrity matters to an
// authority other than the assessed user.
func boundaryCrossed(exe models.Observation, assessed uint32, haveAssessed bool) bool {
	if exe.Bool(models.AttrExeSetUID) || exe.Bool(models.AttrExeSetGID) {
		return true
	}
	if owner, ok := parseUID(attr(exe, models.AttrExeUID)); ok && haveAssessed && owner != assessed {
		return true
	}
	for _, key := range []string{models.AttrProcessUID, models.AttrProcessEUID} {
		if value, ok := parseUID(attr(exe, key)); ok && haveAssessed && value != assessed {
			return true
		}
	}
	return false
}

func privilegedExecutable(exe models.Observation) bool {
	owner, ok := parseUID(attr(exe, models.AttrExeUID))
	return ok && owner == 0 && exe.Bool(models.AttrExeSetUID)
}

// executableWorldWritable reports whether the executable's mode bits grant
// write access to "other".
func executableWorldWritable(exe models.Observation) bool {
	mode, err := strconv.ParseUint(attr(exe, models.AttrExeMode), 8, 32)
	if err != nil {
		return false
	}
	return mode&0o002 != 0
}

func groupRootExecutable(exe models.Observation) bool {
	group, ok := parseUID(attr(exe, models.AttrExeGID))
	return ok && group == 0 && exe.Bool(models.AttrExeSetGID)
}

// firstInconsistency returns the first path-level attribute that differs
// between observations of one executable, or "" when they agree.
func firstInconsistency(members []models.Observation) string {
	keys := []string{
		models.AttrParentPath, models.AttrParentUID, models.AttrParentMode,
		models.AttrParentSticky, models.AttrParentEffectiveWrite,
		models.AttrParentEffectiveExec, models.AttrParentACLStatus,
		models.AttrExeUID, models.AttrExeGID, models.AttrExeMode,
		models.AttrExeSetUID, models.AttrExeSetGID,
		models.AttrParentNosuid, models.AttrParentNoexec,
	}
	for _, key := range keys {
		first := attr(members[0], key)
		for _, member := range members[1:] {
			if attr(member, key) != first {
				return key
			}
		}
	}
	return ""
}

func mountFlag(exe models.Observation, parentKey, exeKey string) string {
	if value, ok := exe.Attr(parentKey); ok && value != "" {
		return value
	}
	value, _ := exe.Attr(exeKey)
	return value
}

func accessValue(value string) acl.Access {
	switch value {
	case string(acl.Allowed), "true":
		return acl.Allowed
	case string(acl.Denied), "false":
		return acl.Denied
	default:
		return acl.Unknown
	}
}

func executionEUID(obs interfaces.ObservationSet) string {
	for _, contextObs := range obs.ByKind(models.KindExecutionContext) {
		if euid, ok := contextObs.Attr(models.AttrEUID); ok {
			return euid
		}
	}
	return ""
}

func parseUID(value string) (uint32, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

func attr(obs models.Observation, key string) string {
	value, _ := obs.Attr(key)
	return value
}
