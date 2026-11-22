// Package identity contains rules about users, groups and privilege grants.
package identity

import (
	"context"
	"strconv"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// uidZeroRule implements NULQ-ID-004: non-root UID-0 accounts.
type uidZeroRule struct{}

// NewUIDZeroRule constructs the rule.
func NewUIDZeroRule() interfaces.Rule { return uidZeroRule{} }

// Metadata implements interfaces.Rule.
func (r uidZeroRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-ID-004",
		Version:     "1.0.0",
		Name:        "Non-root UID-0 accounts",
		Description: "Any account other than root with UID 0 has root authority and is a privilege-escalation target.",
		Category:    "identity",
		Module:      "identity",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindUserAccount},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r uidZeroRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, account := range obs.ByKind(models.KindUserAccount) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		if account.Status != models.StatusComplete {
			continue
		}
		uidStr, _ := account.Attr(models.AttrUserUID)
		uid, err := strconv.Atoi(uidStr)
		if err != nil || uid != 0 {
			continue
		}
		username, _ := account.Attr(models.AttrUserName)
		if username == "root" {
			continue
		}

		resource := "user:" + username
		finding := models.NewFinding(meta, resource, models.ResourceUser,
			models.SeverityHigh, models.ConfidenceHigh,
			"Non-root account has UID 0 (root authority)", now)
		finding.Explanation = "The account " + username + " has UID 0, which the kernel treats as root. " +
			"Any compromise of this account is equivalent to root compromise."
		shell, _ := account.Attr(models.AttrUserShell)
		if shell != "" {
			finding.Explanation += " Its login shell is " + shell + "."
		}
		home, _ := account.Attr(models.AttrUserHome)
		if home != "" {
			finding.Explanation += " Its home directory is " + home + "."
		}
		finding.Impact = "UID 0 bypasses all discretionary access control. " +
			"An attacker who gains access to this account has full root authority."
		finding.Remediation = "Remove the UID 0 assignment from any account other than root. " +
			"Use sudo or dedicated service accounts instead of sharing UID 0."
		finding.Limitations = []string{
			"NULQ reads /etc/passwd only; it does not inspect /etc/shadow, PAM configuration or name-service switches.",
			"An account with UID 0 and a non-login shell (for example /usr/sbin/nologin) still has root authority for setuid programs.",
		}
		finding.AddEvidence(
			builder.Add(account, models.AttrUserUID, "UID field from /etc/passwd."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// ensure uidZeroRule implements interfaces.Rule at compile time.
var _ interfaces.Rule = uidZeroRule{}
