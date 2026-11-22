// Package filesystem contains rules about permission and ownership
// relationships on the local filesystem.
package filesystem

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// privilegedFileCaps are capability bits that can bypass DAC or MAC
// enforcement when present in a file's permitted or inheritable set.
var privilegedFileCaps = map[string]struct{}{
	"00000004": {}, // CAP_DAC_OVERRIDE (bit 2)
	"00000008": {}, // CAP_DAC_READ_SEARCH (bit 3)
	"00100000": {}, // CAP_SYS_ADMIN (bit 21)
	"00010000": {}, // CAP_SETPCAP (bit 16)
	"00000020": {}, // CAP_NET_ADMIN (bit 5)
}

// fileCapabilityRule implements the NULQ-FS-005 rule about file capabilities.
type fileCapabilityRule struct{}

// NewFileCapabilityRule constructs the rule.
func NewFileCapabilityRule() interfaces.Rule { return fileCapabilityRule{} }

// Metadata implements interfaces.Rule.
func (r fileCapabilityRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-FS-005",
		Version:     "1.0.0",
		Name:        "File capability inventory",
		Description: "An executable carries Linux file capabilities in its security.capability xattr, granting it privileges beyond those of its executing user. File capabilities are a finer-grained alternative to set-user-ID and can elevate a process without a set-user-ID bit.",
		Category:    "capabilities",
		Module:      "filesystem",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindFile},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r fileCapabilityRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, file := range obs.ByKind(models.KindFile) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		permitted, hasPermitted := file.Attr(models.AttrFileCapPermitted)
		inheritable, hasInheritable := file.Attr(models.AttrFileCapInheritable)
		effective, hasEffective := file.Attr(models.AttrFileCapEffective)

		if !hasPermitted && !hasInheritable && !hasEffective {
			continue
		}

		if permitted == "" && inheritable == "" && effective == "" {
			continue
		}

		matched := capabilityBits(strings.Join([]string{permitted, inheritable, effective}, ","))
		rootOwned := false
		if ownerUID, ok := file.Attr(models.AttrOwnerUID); ok && ownerUID == "0" {
			rootOwned = true
		}

		severity := models.SeverityLow
		title := "Executable carries file capabilities"
		switch {
		case rootOwned && len(matched) > 0:
			severity = models.SeverityMedium
			title = "Root-owned executable carries privilege-bypassing file capabilities"
		case len(matched) > 0:
			severity = models.SeverityLow
			title = "Executable carries privilege-bypassing file capabilities"
		}

		finding := models.NewFinding(meta, file.Resource, models.ResourceFile, severity, models.ConfidenceHigh, title, now)
		finding.Explanation = fmt.Sprintf(
			"%s carries file capabilities: permitted=%s inheritable=%s effective=%s.",
			file.Resource, permitted, inheritable, effective)
		if len(matched) > 0 {
			finding.Explanation += " The following bits can bypass discretionary or mandatory access control: " +
				strings.Join(matched, ", ") + "."
		}
		finding.Impact = "A process executing this binary gains the capabilities in its permitted set, " +
			"potentially widening its authority beyond that of the invoking user. File capabilities do not require " +
			"a set-user-ID bit and are invisible to traditional SUID auditing."
		finding.Remediation = "Remove unnecessary file capabilities with setcap -r. Scope capabilities to the minimum " +
			"required and audit which executables carry them."
		finding.Limitations = []string{
			"The inheritable set matters only when the executing process also has the capability in its bounding set.",
			"Capability presence does not imply exploitability; binary logic and runtime behaviour are not analysed.",
		}

		evidenceKeys := []string{}
		if hasPermitted {
			evidenceKeys = append(evidenceKeys, models.AttrFileCapPermitted)
		}
		if hasInheritable {
			evidenceKeys = append(evidenceKeys, models.AttrFileCapInheritable)
		}
		if hasEffective {
			evidenceKeys = append(evidenceKeys, models.AttrFileCapEffective)
		}
		for _, key := range evidenceKeys {
			finding.AddEvidence(builder.Add(file, key, "File capability set read from the security.capability xattr."))
		}
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

// capabilityBits returns the names of privilege-bypassing capability bits set
// in any of the comma-separated hex masks.
func capabilityBits(masks string) []string {
	parts := strings.Split(masks, ",")
	seen := make(map[string]struct{})
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := strconv.ParseUint(part, 16, 64)
		if err != nil {
			continue
		}
		for bit := range privilegedFileCaps {
			b, err := strconv.ParseUint(bit, 16, 64)
			if err != nil {
				continue
			}
			if parsed&b != 0 {
				if _, ok := seen[bit]; !ok {
					seen[bit] = struct{}{}
					out = append(out, bit)
				}
			}
		}
	}
	sortStrings(out)
	return out
}

// sortStrings sorts a string slice in place.
func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
