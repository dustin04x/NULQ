// Package system contains rules about kernel and platform hardening.
package system

import (
	"context"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// sshdConfigRule implements NULQ-SYS-009: insecure sshd_config settings.
type sshdConfigRule struct{}

// NewSSHDConfigRule constructs the rule.
func NewSSHDConfigRule() interfaces.Rule { return sshdConfigRule{} }

// Metadata implements interfaces.Rule.
func (r sshdConfigRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-009",
		Version:     "1.0.0",
		Name:        "SSH daemon configuration hardening",
		Description: "sshd settings that permit remote root login, password authentication or X11 forwarding expand remote attack surface.",
		Category:    "ssh",
		Module:      "system",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindSSHDConfig},
		Platforms:   []string{"linux"},
	}
}

// sshdExpectation describes one directive expectation.
type sshdExpectation struct {
	directive   string
	insecure    []string
	severity    models.Severity
	rationale   string
	remediation string
}

// sshdExpectations is a conservative baseline for sshd_config directives.
var sshdExpectations = []sshdExpectation{
	{
		directive:   "permitrootlogin",
		insecure:    []string{"yes", "without-password"},
		severity:    models.SeverityHigh,
		rationale:   "Direct root login over SSH removes a privilege boundary and exposes root credentials to network attacks.",
		remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config and use sudo for root access.",
	},
	{
		directive:   "passwordauthentication",
		insecure:    []string{"yes"},
		severity:    models.SeverityMedium,
		rationale:   "Password authentication is vulnerable to credential stuffing and brute-force attacks.",
		remediation: "Set PasswordAuthentication no and use public-key authentication.",
	},
	{
		directive:   "x11forwarding",
		insecure:    []string{"yes"},
		severity:    models.SeverityLow,
		rationale:   "X11 forwarding can be abused for keystroke injection and screen capture from remote X11 clients.",
		remediation: "Set X11Forwarding no unless X11 forwarding is explicitly required.",
	},
}

// Evaluate implements interfaces.Rule.
func (r sshdConfigRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, config := range obs.ByKind(models.KindSSHDConfig) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		if config.Status != models.StatusComplete {
			continue
		}

		directives, _ := config.Attr(models.AttrSSHDirective)
		if directives == "" {
			continue
		}

		set := make(map[string]string)
		for _, line := range strings.Split(directives, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			set[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}

		for _, expectation := range sshdExpectations {
			if err := ctx.Err(); err != nil {
				return models.RuleResult{}, err
			}
			value, present := set[expectation.directive]
			if !present {
				continue
			}
			insecure := false
			for _, bad := range expectation.insecure {
				if strings.EqualFold(value, bad) {
					insecure = true
					break
				}
			}
			if !insecure {
				continue
			}

			finding := models.NewFinding(meta, config.Resource, models.ResourceFile,
				expectation.severity, models.ConfidenceHigh,
				"sshd permits "+expectation.directive+"="+value, now)
			finding.Explanation = "sshd_config sets " + expectation.directive + "=" + value + ". " + expectation.rationale
			finding.Impact = "A remote attacker can exploit this weak SSH setting to gain or escalate access. " +
				"The risk is highest when combined with exposed network services."
			finding.Remediation = expectation.remediation
			finding.Limitations = []string{
				"NULQ reads sshd_config but does not evaluate Match blocks, Include directives or conditional configuration.",
				"The effective setting may differ if a later Include or Match block overrides it.",
				"Finding presence does not mean the SSH port is exposed to the network.",
			}
			finding.AddEvidence(
				builder.Add(config, models.AttrSSHDirective+"."+expectation.directive,
					"sshd_config directive value for "+expectation.directive),
			)
			findings = append(findings, finding)
		}
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// ensure sshdConfigRule implements interfaces.Rule at compile time.
var _ interfaces.Rule = sshdConfigRule{}
