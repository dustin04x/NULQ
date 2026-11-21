// Package filesystem contains rules about permission and ownership
// relationships on the local filesystem.
package filesystem

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// standardBinaryDirs are locations where distribution packaging places
// privileged executables. A SUID binary outside these directories deserves
// additional review, but presence inside them is not a weakness by itself.
var standardBinaryDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib",
	"/usr/lib32", "/usr/lib64", "/usr/libexec", "/lib", "/lib32",
	"/lib64", "/libexec",
}

type suidRule struct{}

// NewSUIDRule constructs the rule.
func NewSUIDRule() interfaces.Rule { return suidRule{} }

// Metadata implements interfaces.Rule.
func (r suidRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-FS-001",
		Version:     "2.0.0",
		Name:        "Set-owner-ID executable inventory",
		Description: "A regular file carries the set-user-ID or set-group-ID bit, so executing it grants the effective credentials of its owner or group.",
		Category:    "suid-sgid",
		Module:      "filesystem",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindFile},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r suidRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	var findings []models.Finding
	meta := r.Metadata()
	now := time.Now().UTC()

	for _, file := range obs.ByKind(models.KindFile) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		setuid := file.Bool(models.AttrSetUID)
		setgid := file.Bool(models.AttrSetGID)
		if !setuid && !setgid {
			continue
		}

		path := file.Resource
		owner, _ := file.Attr(models.AttrOwnerUser)
		group, _ := file.Attr(models.AttrGroupName)
		mode, _ := file.Attr(models.AttrMode)
		writable, writableKnown := effectiveWritable(file)
		standard := isStandardBinaryPath(path)
		ownerUID, ownerKnown := file.Attr(models.AttrOwnerUID)
		euid := executionEUID(obs)
		rootOwned := ownerKnown && ownerUID == "0"
		selfOwned := euid != "" && ownerKnown && ownerUID == euid

		nosuid, hasNosuid := file.Attr(models.AttrNosuid)
		nosuidActive := hasNosuid && nosuid == "true"

		// HIGH is reserved for the case where replacing the file grants root:
		// a root-owned executable the current user can rewrite. A writable
		// executable owned by another non-root account is delegated authority,
		// not root. A writable self-owned file crosses no user boundary at all.
		// nosuid prevents SUID/SGID execution semantics on that mount; the
		// writable path remains an integrity issue but not SUID-root escalation.
		rootOwnedWritable := writable == "allowed" && rootOwned && modeExecutable(file) && !nosuidActive

		severity := models.SeverityInfo
		title := "Set-owner-ID executable inventory"
		switch {
		case !modeExecutable(file):
			// The kernel ignores the set-user-ID bit without an execute bit, and
			// the set-group-ID bit on a non-executable regular file means
			// mandatory locking, not privilege. Report the raw metadata as inert
			// inventory instead of inventing authority.
			title = "Set-owner-ID bit on a non-executable file is inert"
		case rootOwnedWritable:
			severity = models.SeverityHigh
			title = "Root-owned privileged executable is writable by the current user"
		case writable == "allowed" && ownerKnown && !rootOwned && !selfOwned:
			severity = models.SeverityMedium
			title = "Privileged executable owned by another account is writable"
		case writable == "allowed" && selfOwned:
			severity = models.SeverityLow
			title = "Privileged executable is owned and writable by the current user"
		case setuid && ownerKnown && !rootOwned && !selfOwned:
			severity = models.SeverityLow
			title = "Set-user-ID executable is owned by a non-root account"
		case !standard:
			severity = models.SeverityLow
			title = "Privileged executable outside standard system directories"
		}

		executable := modeExecutable(file)
		finding := models.NewFinding(meta, path, models.ResourceFile, severity, models.ConfidenceHigh, title, now)
		if executable {
			finding.Explanation = fmt.Sprintf(
				"%s has mode %s (owner %s, group %s). %s",
				path, mode, owner, group, describeOwnerBits(setuid, setgid, owner, group))
		} else {
			finding.Explanation = fmt.Sprintf(
				"%s has mode %s (owner %s, group %s). No execute bit is set, so the kernel ignores the set-user-ID bit; "+
					"for a regular file the set-group-ID bit denotes mandatory locking rather than privilege.",
				path, mode, owner, group)
		}
		finding.Impact = "If this executable can be influenced through arguments, environment, configuration or a flaw in its logic, " +
			"a local user may execute code with the owner's effective authority. Presence of the bit is not evidence of exploitability."
		finding.Remediation = "Remove the set-user-ID or set-group-ID bit if it is not required. Prefer file capabilities scoped to a single privilege, " +
			"and mount filesystems holding untrusted executables with nosuid."
		finding.Limitations = []string{
			"Only file mode, ownership, normalized ACL and mount metadata were inspected; binary logic, linked libraries and configuration influence paths are not analysed.",
			"Security-module policy, capabilities and runtime execution were not evaluated.",
		}
		if !writableKnown {
			finding.Limitations = append(finding.Limitations,
				"Effective write permission could not be determined; the finding does not claim the file is safely non-writable.")
		}
		switch {
		case !executable:
			finding.Impact = "The bit is inert metadata: no execute bit is set, so it cannot grant the owner's or group's credentials."
			finding.Remediation = "Remove the unused bit during routine cleanup; no privilege is granted by it."
		case rootOwnedWritable:
			finding.Impact = "The current user can replace the contents of a root-owned privileged executable, which turns the observed permission relationship into direct root authority."
			finding.Remediation = "Restore root ownership and restrictive modes immediately, then investigate how the file became writable."
		case writable == "allowed" && rootOwned && nosuidActive:
			finding.Impact = "The file is writable and carries SUID/SGID bits, but the containing mount has nosuid set. nosuid prevents SUID/SGID execution semantics on that mount; the path remains an integrity concern but not direct SUID-root escalation through this mount."
			finding.Remediation = "Restore restrictive ownership and modes. Do not treat nosuid as a substitute for file integrity."
		case writable == "allowed" && selfOwned:
			finding.Impact = "The current user already controls this executable and runs it with their own credentials, so no user boundary is crossed. A set-group-ID bit can still grant a group the user does not hold."
			finding.Remediation = "No ownership change is needed. Remove the set-owner-ID bit if group authority is not intended; otherwise ensure only trusted content is executed."
		case writable == "allowed":
			finding.Impact = "The executable is not integrity-controlled by an administrative account. Users who execute it receive the owner's authority, and its behaviour can change without a packaging update. This is delegated authority, not root."
			finding.Remediation = "If the owner is not the intended account, restore ownership and modes. If the user legitimately owns the executable, remove the set-owner-ID bit and use a capability or a user-scoped tool instead."
		}
		if nosuidActive && executable {
			finding.Explanation += fmt.Sprintf(" The containing mount (%s) has nosuid set; SUID/SGID execution semantics are constrained on that mount.", mountPoint(file))
		}

		finding.AddEvidence(
			builder.Add(file, models.AttrMode, "Observed permission bits including the set-owner-ID bits."),
			builder.Add(file, models.AttrSetUID, "Whether the set-user-ID bit is set."),
			builder.Add(file, models.AttrSetGID, "Whether the set-group-ID bit is set."),
			builder.Add(file, models.AttrOwnerUser, "Account whose effective credentials the executable receives."),
			builder.Add(file, models.AttrOwnerUID, "Numeric owner compared with the assessed effective UID."),
			builder.Add(file, models.AttrWritableByCurrentUser, "Whether the running user could modify the executable by mode/legacy assessment."),
		)
		if value, ok := file.Attr(models.AttrEffectiveWrite); ok {
			finding.AddEvidence(builder.Add(file, models.AttrEffectiveWrite, "Effective write permission for the assessed identity (value: "+value+"."))
		}
		if _, ok := file.Attr(models.AttrNosuid); ok {
			finding.AddEvidence(builder.Add(file, models.AttrNosuid, "Mount nosuid flag affecting SUID/SGID execution semantics."))
			finding.AddEvidence(builder.Add(file, models.AttrMountPoint, "Resolved containing mount."))
		}
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

func describeOwnerBits(setuid, setgid bool, owner, group string) string {
	switch {
	case setuid && setgid:
		return fmt.Sprintf("Because both bits are set, execution grants the effective credentials of user %s and group %s.", owner, group)
	case setuid:
		return fmt.Sprintf("Because the set-user-ID bit is set, execution grants the effective credentials of user %s.", owner)
	default:
		return fmt.Sprintf("Because the set-group-ID bit is set, execution grants the effective credentials of group %s.", group)
	}
}

// modeExecutable reports whether any execute bit is set. A set-owner-ID bit
// without one has no privilege effect and must not be escalated.
func modeExecutable(file models.Observation) bool {
	mode, ok := file.Attr(models.AttrMode)
	if !ok || mode == "" {
		return false
	}
	parsed, err := strconv.ParseUint(mode, 8, 32)
	return err == nil && parsed&0o111 != 0
}

func isStandardBinaryPath(path string) bool {
	cleaned := filepath.Clean(path)
	for _, dir := range standardBinaryDirs {
		if strings.HasPrefix(cleaned, dir+"/") {
			return true
		}
	}
	return false
}

func mountPoint(obs models.Observation) string {
	if point, ok := obs.Attr(models.AttrMountPoint); ok && point != "" {
		return point
	}
	return "<unknown mount>"
}
