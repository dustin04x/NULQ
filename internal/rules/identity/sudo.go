// Package identity contains rules about users, groups and privilege grants.
package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// sudoRule implements NULQ-ID-002: sudoers policy inventory.
type sudoRule struct{}

// NewSudoRule constructs the rule.
func NewSudoRule() interfaces.Rule { return sudoRule{} }

// Metadata implements interfaces.Rule.
func (r sudoRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-ID-002",
		Version:     "1.0.0",
		Name:        "Sudoers policy inventory",
		Description: "A sudoers rule grants a user or group the right to run commands as another user, potentially as root, without a password. NULQ only inventories these rules; it never invokes sudo.",
		Category:    "sudo",
		Module:      "identity",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindSudoRule},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r sudoRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, ruleObs := range obs.ByKind(models.KindSudoRule) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		if ruleObs.Status != models.StatusComplete {
			continue
		}

		commands, _ := ruleObs.Attr(models.AttrSudoCommands)
		if commands == "" {
			continue
		}

		resource := ruleObs.Resource
		lines := strings.Split(commands, "\n")
		nopasswd := false
		rootRunAs := false
		for _, line := range lines {
			l := strings.ToLower(line)
			if strings.Contains(l, "nopasswd") {
				nopasswd = true
			}
			if strings.Contains(l, "(root)") || strings.Contains(l, "( :root)") {
				rootRunAs = true
			}
		}

		severity := models.SeverityLow
		title := "Sudoers rule permits command execution as another user"
		if rootRunAs && nopasswd {
			severity = models.SeverityMedium
			title = "Sudoers rule permits passwordless execution as root"
		} else if rootRunAs {
			severity = models.SeverityLow
			title = "Sudoers rule permits execution as root"
		}

		finding := models.NewFinding(meta, resource, models.ResourceFile, severity, models.ConfidenceHigh, title, now)
		finding.Explanation = fmt.Sprintf(
			"%s contains %d sudoers rule line(s). These grant named users or groups the right to run specified commands as another user.",
			resource, len(lines))
		if nopasswd {
			finding.Explanation += " Some rules use NOPASSWD, so no authentication is required."
		}
		if rootRunAs {
			finding.Explanation += " Some rules permit execution as root."
		}
		finding.Impact = "A user who matches a sudoers rule can execute commands with elevated authority. " +
			"Passwordless rules are higher risk because they remove an interactive authentication step."
		finding.Remediation = "Review each sudoers rule and restrict commands to the minimum necessary. " +
			"Avoid NOPASSWD for root execution unless required by automation."
		finding.Limitations = []string{
			"NULQ parses rule lines but does not evaluate sudoers syntax, aliases, includes or netgroups.",
			"Rule presence does not mean a given user can invoke it; user matching is not analysed.",
			"NULQ never invokes sudo and does not test whether a rule is effective.",
		}
		finding.AddEvidence(
			builder.Add(ruleObs, models.AttrSudoCommands, "Sudoers rule lines observed from the file."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
