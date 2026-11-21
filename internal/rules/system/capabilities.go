package system

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// privilegeBypassingCapabilities are capabilities that can bypass DAC or MAC
// enforcement. Presence alone is not a finding; it is a hardening signal that
// matters most when combined with elevated effective UID.
var privilegeBypassingCapabilities = map[string]struct{}{
	"00000004": {}, // CAP_DAC_OVERRIDE (bit 2)
	"00000008": {}, // CAP_DAC_READ_SEARCH (bit 3)
	"00100000": {}, // CAP_SYS_ADMIN (bit 21)
	"00010000": {}, // CAP_SETPCAP (bit 16)
}

type capabilitiesRule struct{}

// NewCapabilitiesRule constructs the rule.
func NewCapabilitiesRule() interfaces.Rule { return capabilitiesRule{} }

// Metadata implements interfaces.Rule.
func (r capabilitiesRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-003",
		Version:     "1.0.0",
		Name:        "Process capability surface",
		Description: "Processes with privilege-bypassing capabilities in their effective set expand what local compromise can achieve, especially when running as root.",
		Category:    "capabilities",
		Module:      "system",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindProcess, models.KindExecutionContext},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r capabilitiesRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
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

		capEff, ok := proc.Attr(models.AttrCapEffective)
		if !ok || capEff == "" {
			continue
		}

		matched := capabilityBits(capEff)
		if len(matched) == 0 {
			continue
		}

		isRoot := euid == "0"
		severity := models.SeverityInfo
		if isRoot {
			severity = models.SeverityMedium
		}

		finding := models.NewFinding(meta, proc.Resource, models.ResourceProcess,
			severity, models.ConfidenceMedium,
			"Process holds privilege-bypassing capabilities", now)
		finding.Explanation = "Process " + proc.Resource + " (euid=" + euid + ") has effective capability bits " +
			strings.Join(matched, ", ") + " which can bypass discretionary or mandatory access control. " +
			"Capability presence is a hardening signal, not an exploit."
		if isRoot {
			finding.Impact = "A root process with privilege-bypassing capabilities can override file ownership and permission checks, " +
				"increasing the impact of any compromise."
		} else {
			finding.Impact = "An unprivileged process with privilege-bypassing capabilities has a broader local attack surface " +
				"than one without, but cannot alone cross into root authority."
		}
		finding.Remediation = "Drop unnecessary capabilities from the process's capability bounding set at launch (CapabilityBoundingSet= in systemd, or capsh --drop)."
		finding.Limitations = []string{
			"Capability bounding set may be smaller than the effective set; only the effective set is reported.",
			"File capabilities (security.capability xattr) on the executable are not read by this rule.",
			"Capability presence does not imply exploitability.",
		}
		finding.AddEvidence(
			builder.Add(proc, models.AttrProcessEUID, "Effective user ID of the process."),
			builder.Add(proc, models.AttrCapEffective, "Hex-encoded effective capability bits from /proc/<pid>/Status."),
		)
		findings = append(findings, finding)
	}

	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// capabilityBits returns the names of privilege-bypassing capability bits set
// in a hex-encoded capability mask.
func capabilityBits(mask string) []string {
	parsed, err := strconv.ParseUint(mask, 16, 64)
	if err != nil {
		return nil
	}
	var out []string
	for bit := range privilegeBypassingCapabilities {
		b, err := strconv.ParseUint(bit, 16, 64)
		if err != nil {
			continue
		}
		if parsed&b != 0 {
			out = append(out, bit)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
