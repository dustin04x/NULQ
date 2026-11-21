package system

import (
	"context"
	"strconv"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type usernsRule struct{}

// NewUsernsRule constructs the rule.
func NewUsernsRule() interfaces.Rule { return usernsRule{} }

// Metadata implements interfaces.Rule.
func (r usernsRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-006",
		Version:     "1.0.0",
		Name:        "Unprivileged user namespace clone enabled",
		Description: "The kernel allows unprivileged users to create user namespaces, widening the kernel attack surface reachable from unprivileged processes.",
		Category:    "kernel-hardening",
		Module:      "system",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindSysctl},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r usernsRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	const key = "kernel.unprivileged_userns_clone"

	for _, param := range obs.ByKind(models.KindSysctl) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		if param.Resource != key {
			continue
		}
		if param.Status != models.StatusComplete {
			continue
		}

		value, ok := param.Attr(models.AttrValue)
		if !ok || value == "" {
			continue
		}

		parsed, err := strconv.Atoi(value)
		if err != nil {
			continue
		}

		// Only flag when the parameter exists and is non-zero. Absent means
		// the kernel does not expose it: no finding, never assumed secure.
		if parsed == 0 {
			continue
		}

		finding := models.NewFinding(meta, key, models.ResourceSysctl,
			models.SeverityInfo, models.ConfidenceHigh,
			"Unprivileged user namespace clone is enabled", now)
		finding.Explanation = "kernel.unprivileged_userns_clone is " + value +
			", allowing unprivileged users to create user namespaces. " +
			"This widens the kernel surface reachable by unprivileged local processes."
		finding.Impact = "User namespaces have been a recurring source of kernel privilege-escalation primitives. " +
			"Enabling them for unprivileged users increases exploitability of kernel bugs."
		finding.Remediation = "Set kernel.unprivileged_userns_clone=0 in /etc/sysctl.d/ or at boot, unless a workload requires unprivileged namespaces."
		finding.Limitations = []string{
			"This rule does not assess whether a known exploit applies to the running kernel.",
			"Some containers and sandboxed workloads require unprivileged namespaces to function.",
		}
		finding.AddEvidence(
			builder.AddExpected(param, models.AttrValue, "0", "Current kernel parameter value."),
		)
		return models.RuleResult{Findings: []models.Finding{finding}, Evidence: builder.Items()}, nil
	}

	return models.RuleResult{Findings: nil, Evidence: nil}, nil
}
