// Package system contains rules about kernel, security modules and environment.
package system

import (
	"context"
	"fmt"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// kernelMitigationRule implements NULQ-SYS-007: kernel hardware vulnerability mitigations.
type kernelMitigationRule struct{}

// NewKernelMitigationRule constructs the rule.
func NewKernelMitigationRule() interfaces.Rule { return kernelMitigationRule{} }

// Metadata implements interfaces.Rule.
func (r kernelMitigationRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-007",
		Version:     "1.0.0",
		Name:        "Kernel hardware vulnerability mitigations",
		Description: "The kernel exposes hardware vulnerability mitigation status (Spectre, Meltdown, L1TF, MDS, etc.) through sysfs. NULQ records whether each mitigation is active, partial or absent.",
		Category:    "kernel-hardening",
		Module:      "system",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindKernelMitigation},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r kernelMitigationRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, mit := range obs.ByKind(models.KindKernelMitigation) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		if mit.Status != models.StatusComplete {
			continue
		}

		name, _ := mit.Attr(models.AttrMitigationName)
		value, _ := mit.Attr(models.AttrMitigationValue)
		status, _ := mit.Attr(models.AttrMitigationStatus)

		severity := models.SeverityInfo
		title := fmt.Sprintf("Kernel mitigation status: %s", name)
		switch status {
		case "vulnerable":
			severity = models.SeverityMedium
			title = fmt.Sprintf("Kernel vulnerability is unmitigated: %s", name)
		case "mitigation_partial":
			severity = models.SeverityLow
			title = fmt.Sprintf("Kernel mitigation is partial: %s", name)
		case "not_affected":
			continue // No finding for hardware that is not affected
		}

		finding := models.NewFinding(meta, mit.Resource, models.ResourceSysctl, severity, models.ConfidenceHigh, title, now)
		finding.Explanation = fmt.Sprintf(
			"Kernel reports %q status %q for hardware vulnerability %s. Value: %s.",
			status, value, mit.Resource, value)
		finding.Impact = "An unmitigated or partially mitigated hardware vulnerability may be exploitable " +
			"by local processes to leak memory or bypass isolation boundaries."
		finding.Remediation = "Update the kernel and firmware, enable mitigations via boot parameters, " +
			"and consult the distribution's hardening guidance for each vulnerability."
		finding.Limitations = []string{
			"Mitigation status is read from sysfs; NULQ does not test whether an exploit applies to the running kernel.",
			"Some mitigations carry performance costs and may be intentionally disabled.",
		}
		finding.AddEvidence(
			builder.Add(mit, models.AttrMitigationValue, "Kernel-reported mitigation status value."),
			builder.Add(mit, models.AttrMitigationStatus, "Normalised mitigation status."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
