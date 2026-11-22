package filesystem

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// pathEntryRule implements the NULQ-FS-003 rule about unsafe PATH directories.
type pathEntryRule struct{}

// NewPathEntryRule constructs the rule.
func NewPathEntryRule() interfaces.Rule { return pathEntryRule{} }

// Metadata implements interfaces.Rule.
func (r pathEntryRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-FS-003",
		Version:     "1.0.0",
		Name:        "Unsafe PATH directory",
		Description: "A PATH entry is empty, relative, or writable by the current user. This is a command-resolution precondition; the rule does not observe a privileged consumer and therefore does not establish a privilege boundary by itself.",
		Category:    "path-hijack",
		Module:      "filesystem",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindPathEntry},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
// Without an observed privileged consumer, a writable PATH entry is a
// contextual weakness, not a demonstrated privilege boundary. Every case is
// therefore LOW, and the finding says which relationship is missing.
func (r pathEntryRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()
	effectiveUID := executionEUID(obs)

	var findings []models.Finding
	for _, entry := range obs.ByKind(models.KindPathEntry) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		value, _ := entry.Attr(models.AttrPathEntry)
		index, _ := entry.Attr(models.AttrPathIndex)

		pathExists, _ := entry.Attr(models.AttrPathExists)
		if pathExists == "false" && value != "" {
			continue
		}

		var title, explanation, impact, remediation string

		if value == "" {
			title = "PATH contains an empty entry"
			explanation = fmt.Sprintf(
				"PATH index %s is empty, which POSIX shells interpret as the current working directory.", index)
			impact = "Running a command by name can execute a same-named file from the working directory. " +
				"No privileged consumer of this PATH was observed, so privilege escalation is not established."
			remediation = "Remove the empty element from PATH."
		} else if !filepath.IsAbs(value) {
			title = "PATH contains a relative entry"
			explanation = fmt.Sprintf("PATH index %s is %q, a relative path resolved against the working directory.", index, value)
			impact = "Command resolution depends on the directory the user happens to be in. " +
				"No privileged consumer of this PATH was observed, so privilege escalation is not established."
			remediation = "Replace the relative entry with an absolute path."
		} else {
			writable, _ := effectiveWritable(entry)
			// If write permission is denied, skip this entry
			// (matching the original rule behavior where !WritableByCurrentUser caused a continue).
			if writable == "denied" {
				continue
			}
			// If write is allowed and the directory is owned by the assessed user,
			// report it as normal user-managed directory behavior.
			if writable == "allowed" && effectiveUID != "" && isOwnedBy(entry, effectiveUID) {
				title = "PATH directory is writable by the current user"
				explanation = fmt.Sprintf(
					"%s is owned by the current user and writable by them. This is normal for user-managed tool directories.", value)
				impact = "No privilege boundary is crossed when the current user writes here. Risk arises only if a privileged process resolves commands through this PATH without resetting it, which was not observed."
				remediation = "No action is required for interactive use. Ensure privileged automation sets a trusted PATH or uses absolute command paths."
			} else {
				// Write permission is available (either allowed or denied-but-known,
				// or we have some other situation), and the directory is not owned
				// by the assessed user (or we don't have an effective UID to check).
				title = "PATH directory is writable by the current user but owned by another account"
				explanation = fmt.Sprintf(
					"%s is writable by the current user while owned by another account, so a file placed there precedes later PATH entries when commands are resolved by name.", value)
				impact = "A privileged script or service that resolves commands through this PATH could execute attacker-controlled code. No such consumer was observed, so this remains a precondition rather than a proven exposure."
				remediation = "Remove write access for this account, or remove the directory from PATH. Prefer absolute paths in privileged automation."
			}
		}

		finding := models.NewFinding(meta, entry.Resource, models.ResourcePathEntry, models.SeverityLow, models.ConfidenceHigh, title, now)
		finding.Explanation = explanation
		finding.Impact = impact
		finding.Remediation = remediation
		finding.Limitations = []string{
			"This rule analyses the PATH of the NULQ process, which may differ from the PATH seen by privileged services.",
			"No privileged consumer, sudo secure_path or service manager environment was observed; the execution relationship required for escalation is not established.",
			"Command-name collisions in the directory are not enumerated.",
			"Effective permissions use normalized ACL when available; otherwise fallback to mode-bit writability.",
		}
		finding.AddEvidence(
			builder.Add(entry, models.AttrPathEntry, "The literal PATH entry observed."),
			builder.Add(entry, models.AttrPathIndex, "Position of the entry in PATH."),
			builder.Add(entry, models.AttrWritableByCurrentUser, "Whether the running user could create files in the entry."),
			builder.Add(entry, models.AttrOwnerUser, "Owner of the PATH directory."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// executionEUID extracts the effective UID from an execution context observation.
func executionEUID(obs interfaces.ObservationSet) string {
	for _, contextObs := range obs.ByKind(models.KindExecutionContext) {
		if euid, ok := contextObs.Attr(models.AttrEUID); ok {
			return euid
		}
	}
	return ""
}

// isOwnedBy reports whether the observation's owner UID matches the given uid.
func isOwnedBy(obs models.Observation, uid string) bool {
	if uid == "" {
		return false
	}
	owner, ok := obs.Attr(models.AttrOwnerUID)
	return ok && owner == uid
}

// effectiveWritable returns the effective write permission string and whether
// it was known (checked via AttrEffectiveWrite first, then AttrWritableByCurrentUser).
func effectiveWritable(entry models.Observation) (string, bool) {
	// Check new effective-permission attribute first
	if value, ok := entry.Attr(models.AttrEffectiveWrite); ok {
		switch value {
		case "allowed":
			return "allowed", true
		case "denied":
			return "denied", true
		case "unknown":
			return "unknown", true
		}
	}
	// Fall back to legacy writable-by-current-user attribute
	if value, ok := entry.Attr(models.AttrWritableByCurrentUser); ok {
		switch value {
		case "true":
			return "allowed", true
		case "false":
			return "denied", true
		case "unknown":
			return "unknown", true
		}
	}
	return "", false
}
