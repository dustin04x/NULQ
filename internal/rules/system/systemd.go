package system

import (
	"context"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type systemdRule struct{}

// NewSystemdRule constructs the rule.
func NewSystemdRule() interfaces.Rule { return systemdRule{} }

// Metadata implements interfaces.Rule.
func (r systemdRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-005",
		Version:     "1.0.0",
		Name:        "Systemd unit lacks security hardening directives",
		Description: "Root-run systemd service units without NoNewPrivileges= allow services to gain privileges via execve, weakening defence in depth.",
		Category:    "service-hardening",
		Module:      "system",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindSystemdUnit},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r systemdRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, unit := range obs.ByKind(models.KindSystemdUnit) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		user, _ := unit.Attr(models.AttrSystemdUser)
		noNewPrivs, _ := unit.Attr(models.AttrSystemdNoNewPrivileges)

		// Only flag units running as root (User= root or unset).
		if user != "" && user != "0" && user != "root" {
			continue
		}

		if noNewPrivs == "yes" || noNewPrivs == "true" || noNewPrivs == "1" {
			continue
		}

		finding := models.NewFinding(meta, unit.Resource, models.ResourceSystem,
			models.SeverityLow, models.ConfidenceMedium,
			"Root-run systemd unit lacks NoNewPrivileges", now)
		finding.Explanation = "Systemd unit " + unit.Resource + " runs as root (User=" + user + ") without NoNewPrivileges=yes. " +
			"Execve can grant capabilities to the service, weakening defence in depth."
		finding.Impact = "A vulnerability in the service could lead to full privilege escalation through capabilities " +
			"gained on execve."
		finding.Remediation = "Add NoNewPrivileges=yes to the [Service] section of the unit file, then reload systemd."
		finding.Limitations = []string{
			"Unit file is read from disk; runtime activation state (enabled/active) is not evaluated via D-Bus.",
			"A unit lacking hardening directives may be intentionally unhardened for a specific workload.",
			"ProtectSystem=, ProtectHome= and PrivateTmp= are not checked by this rule.",
		}
		finding.AddEvidence(
			builder.Add(unit, models.AttrSystemdUser, "User= directive from the systemd unit file."),
			builder.Add(unit, models.AttrSystemdNoNewPrivileges, "NoNewPrivileges= directive from the systemd unit file."),
		)
		findings = append(findings, finding)
	}

	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
