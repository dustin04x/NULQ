package system

import (
	"context"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// seccompModeDisabled is the seccomp mode value meaning no seccomp filter.
const seccompModeDisabled = "0"

type seccompRule struct{}

// NewSeccompRule constructs the rule.
func NewSeccompRule() interfaces.Rule { return seccompRule{} }

// Metadata implements interfaces.Rule.
func (r seccompRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-004",
		Version:     "1.0.0",
		Name:        "Seccomp profile presence",
		Description: "Processes running with seccomp disabled and elevated privileges lose a layer of syscall filtering, reducing defence in depth.",
		Category:    "sandboxing",
		Module:      "system",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceLow,
		Required:    []models.Kind{models.KindProcess},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r seccompRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, proc := range obs.ByKind(models.KindProcess) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		euid, ok := proc.Attr(models.AttrProcessEUID)
		if !ok || euid == "" {
			continue
		}

		seccomp, ok := proc.Attr(models.AttrSeccomp)
		if !ok || seccomp == "" {
			continue
		}

		// Only flag seccomp disabled when running as root. Unprivileged
		// processes with seccomp disabled are common and not flagged.
		if seccomp != seccompModeDisabled || euid != "0" {
			continue
		}

		finding := models.NewFinding(meta, proc.Resource, models.ResourceProcess,
			models.SeverityInfo, models.ConfidenceLow,
			"Privileged process with seccomp disabled", now)
		finding.Explanation = "Process " + proc.Resource + " (euid=0) runs with seccomp mode " + seccomp +
			" (disabled). No syscall filter is applied, reducing defence in depth for a privileged process."
		finding.Impact = "A compromised privileged process without seccomp filtering can make any syscall available " +
			"to its privilege level, increasing exploit reliability."
		finding.Remediation = "Enable seccomp filtering for privileged services (Seccomp= in systemd, or prctl(PR_SET_SECCOMP))."
		finding.Limitations = []string{
			"Seccomp mode is a single observable flag; the BPF filter content is not read.",
			"Seccomp absence does not imply exploitability.",
		}
		finding.AddEvidence(
			builder.Add(proc, models.AttrProcessEUID, "Effective user ID of the process."),
			builder.Add(proc, models.AttrSeccomp, "Seccomp mode from /proc/<pid>/status (0=disabled, 1=filter, 2=strict)."),
		)
		findings = append(findings, finding)
	}

	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
