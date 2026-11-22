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

// containerIndicatorRule implements NULQ-SYS-008: container/runtime indicators.
type containerIndicatorRule struct{}

// NewContainerIndicatorRule constructs the rule.
func NewContainerIndicatorRule() interfaces.Rule { return containerIndicatorRule{} }

// Metadata implements interfaces.Rule.
func (r containerIndicatorRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-008",
		Version:     "1.0.0",
		Name:        "Container runtime indicators",
		Description: "Marker files and sockets indicate the assessment target is a container or has container runtime tooling installed. NULQ never connects to the Docker socket or contacts any runtime.",
		Category:    "containers",
		Module:      "system",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindContainerIndicator},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r containerIndicatorRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, indicator := range obs.ByKind(models.KindContainerIndicator) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		if indicator.Status != models.StatusComplete {
			continue
		}

		dockerSocket, _ := indicator.Attr(models.AttrDockerSocket)
		containerMount, _ := indicator.Attr(models.AttrContainerMount)

		severity := models.SeverityInfo
		title := "Container indicator observed"
		switch {
		case dockerSocket == "true":
			severity = models.SeverityLow
			title = "Docker socket is present"
		case containerMount == "true":
			title = "Container marker file present"
		}

		finding := models.NewFinding(meta, indicator.Resource, models.ResourceFile, severity, models.ConfidenceHigh, title, now)
		finding.Explanation = fmt.Sprintf(
			"%s was observed on the assessed system. This indicates container runtime tooling or a containerised assessment target.",
			indicator.Resource)
		if dockerSocket == "true" {
			finding.Explanation += " NULQ never connects to the Docker socket or contacts any container runtime."
		}
		finding.Impact = "Container runtime presence expands the privilege surface: container escapes, socket mounting and runtime configuration are out of scope for this rule."
		finding.Remediation = "If the Docker socket is present and accessible to unprivileged users, restrict its permissions. " +
			"Ensure container runtimes are not exposed to untrusted workloads."
		finding.Limitations = []string{
			"Indicator presence does not mean the runtime is running, accessible or exploitable.",
			"NULQ never connects to any socket or contacts any runtime.",
		}
		if dockerSocket == "true" {
			finding.AddEvidence(builder.Add(indicator, models.AttrDockerSocket, "Docker socket file exists on the assessed system."))
		}
		if containerMount == "true" {
			finding.AddEvidence(builder.Add(indicator, models.AttrContainerMount, "Container marker file exists on the assessed system."))
		}
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
