// Package identity contains rules about users, groups and privilege grants.
package identity

import (
	"context"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// authorizedKeysRule implements NULQ-ID-006: writable authorized_keys files.
type authorizedKeysRule struct{}

// NewAuthorizedKeysRule constructs the rule.
func NewAuthorizedKeysRule() interfaces.Rule { return authorizedKeysRule{} }

// Metadata implements interfaces.Rule.
func (r authorizedKeysRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-ID-006",
		Version:     "1.0.0",
		Name:        "Writable SSH authorized_keys files",
		Description: "An authorized_keys file writable by group or other allows an attacker to inject their own public key and gain account access.",
		Category:    "ssh",
		Module:      "identity",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindSSHAuthorizedKeys},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r authorizedKeysRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, ak := range obs.ByKind(models.KindSSHAuthorizedKeys) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		if ak.Status != models.StatusComplete {
			continue
		}
		writable, _ := ak.Attr(models.AttrAuthKeysWritable)
		if writable != "true" {
			continue
		}

		path, _ := ak.Attr(models.AttrAuthKeysPath)
		finding := models.NewFinding(meta, path, models.ResourceFile,
			models.SeverityMedium, models.ConfidenceHigh,
			"SSH authorized_keys file is writable by group or other", now)
		finding.Explanation = path + " is writable by more than just its owner. " +
			"An attacker who can write to it can append their own public key and log in as this account."
		finding.Impact = "Authorized key injection grants remote interactive access to the account. " +
			"If the account has sudo or UID 0, this becomes root compromise."
		finding.Remediation = "Restrict authorized_keys to owner-only write: chmod 600 " + path + " " +
			"and ensure the parent .ssh directory is not group- or world-writable."
		finding.Limitations = []string{
			"NULQ judges writability from mode bits alone; ACLs, SELinux/AppArmor or immutable flags are not assessed.",
			"The file must exist for NULQ to observe it; accounts without authorized_keys are silent.",
		}
		finding.AddEvidence(
			builder.Add(ak, models.AttrAuthKeysWritable, "Authorized_keys writable flag derived from file mode bits."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// ensure authorizedKeysRule implements interfaces.Rule at compile time.
var _ interfaces.Rule = authorizedKeysRule{}
