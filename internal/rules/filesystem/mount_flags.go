package filesystem

import (
	"context"
	"fmt"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type mountFlagsRule struct{}

// NewMountFlagsRule reports contextual mount-flag relationships. Mount flags
// constrain execution behavior; they are never treated as universal proof of
// safety and never produce escalation findings by themselves.
func NewMountFlagsRule() interfaces.Rule { return mountFlagsRule{} }

func (r mountFlagsRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-FS-004",
		Version:     "1.0.0",
		Name:        "Mount flag constrains or exposes privileged executable behavior",
		Description: "A privileged executable or writable execution surface is observed on a mount whose security-relevant flags affect how the path can be consumed.",
		Category:    "mounts",
		Module:      "filesystem",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindFile, models.KindDirectory, models.KindMount},
		Platforms:   []string{"linux"},
	}
}

func (r mountFlagsRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()
	var findings []models.Finding

	for _, file := range obs.ByKind(models.KindFile) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		if !file.Bool(models.AttrSetUID) && !file.Bool(models.AttrSetGID) {
			continue
		}
		if !modeExecutable(file) {
			continue
		}
		nosuid, hasNosuid := file.Attr(models.AttrNosuid)
		if hasNosuid && nosuid == "true" {
			finding := models.NewFinding(meta, file.Resource, models.ResourceFile,
				models.SeverityInfo, models.ConfidenceHigh,
				"Privileged executable is on a nosuid mount", now)
			finding.Explanation = fmt.Sprintf(
				"%s carries set-owner-ID bits but is on mount %s with nosuid. The nosuid flag prevents set-user-ID and set-group-ID bits from granting their usual execution privileges on that mount.",
				file.Resource, mountPoint(file))
			finding.Impact = "Execution from this mount does not receive the executable owner's credentials through SUID/SGID semantics. This is contextual evidence, not a security weakness and not proof that no other privilege path exists."
			finding.Remediation = "No remediation is required for the mount flag itself. Review whether the privileged bits are intended for this location."
			finding.Limitations = []string{
				"Execution was not observed; the finding describes mount semantics, not runtime behavior.",
				"Other privilege mechanisms outside mount SUID semantics are not evaluated.",
			}
			finding.AddEvidence(
				builder.Add(file, models.AttrSetUID, "Observed set-user-ID bit."),
				builder.Add(file, models.AttrSetGID, "Observed set-group-ID bit."),
				builder.Add(file, models.AttrNosuid, "Mount nosuid flag for the executable path."),
				builder.Add(file, models.AttrMountPoint, "Resolved containing mount."),
			)
			findings = append(findings, finding)
		}
	}

	for _, dir := range obs.ByKind(models.KindDirectory) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		// Report only writable execution surfaces where mount flags materially
		// change interpretation, and only when the directory is otherwise notable.
		noexec, hasNoexec := dir.Attr(models.AttrNoexec)
		if hasNoexec && noexec == "true" && dir.Bool(models.AttrWorldWritable) {
			finding := models.NewFinding(meta, dir.Resource, models.ResourceDirectory,
				models.SeverityInfo, models.ConfidenceMedium,
				"World-writable directory is on a noexec mount", now)
			finding.Explanation = fmt.Sprintf(
				"%s is world-writable but on mount %s with noexec. The noexec flag prevents direct execution from that mount.",
				dir.Resource, mountPoint(dir))
			finding.Impact = "Direct execution from this mount is constrained, but noexec does not prevent every way an interpreter or loader could read or consume content from the directory."
			finding.Remediation = "Treat noexec as a constraint, not a substitute for restricting write access to the directory."
			finding.Limitations = []string{
				"Consumers and interpreters are not enumerated.",
				"Read-based loading, scripts passed to interpreters from other mounts, and kernel-specific behavior are not evaluated.",
			}
			finding.AddEvidence(
				builder.Add(dir, models.AttrWorldWritable, "Directory is writable by other."),
				builder.Add(dir, models.AttrNoexec, "Mount noexec flag for the directory path."),
				builder.Add(dir, models.AttrMountPoint, "Resolved containing mount."),
			)
			findings = append(findings, finding)
		}
	}

	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
