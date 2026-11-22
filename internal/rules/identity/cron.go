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

// cronRule implements NULQ-ID-003: cron job inventory.
type cronRule struct{}

// NewCronRule constructs the rule.
func NewCronRule() interfaces.Rule { return cronRule{} }

// Metadata implements interfaces.Rule.
func (r cronRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-ID-003",
		Version:     "1.0.0",
		Name:        "Cron job inventory",
		Description: "A cron or at job schedules commands to run at fixed times, dates or intervals, typically as root via /etc/cron.* directories. NULQ inventories job files and their writability context.",
		Category:    "cron",
		Module:      "identity",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindCronJob},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r cronRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	var findings []models.Finding
	for _, jobObs := range obs.ByKind(models.KindCronJob) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		if jobObs.Status != models.StatusComplete {
			continue
		}

		commands, _ := jobObs.Attr(models.AttrCronCommand)
		if commands == "" {
			continue
		}

		resource := jobObs.Resource
		lines := strings.Split(commands, "\n")
		owner, _ := jobObs.Attr(models.AttrOwnerUser)
		mode, _ := jobObs.Attr(models.AttrMode)
		writable, _ := jobObs.Attr(models.AttrWritableByCurrentUser)

		severity := models.SeverityLow
		title := "Cron job schedules commands"
		if writable == "allowed" {
			severity = models.SeverityMedium
			title = "Cron job file is writable by the current user"
		}

		finding := models.NewFinding(meta, resource, models.ResourceFile, severity, models.ConfidenceHigh, title, now)
		finding.Explanation = fmt.Sprintf(
			"%s contains %d cron job line(s). Cron jobs run at scheduled times, typically as root when placed in system cron directories.",
			resource, len(lines))
		if owner != "" {
			finding.Explanation += fmt.Sprintf(" The file is owned by %s.", owner)
		}
		if mode != "" {
			finding.Explanation += fmt.Sprintf(" Mode is %s.", mode)
		}
		if writable == "allowed" {
			finding.Explanation += " The current user can modify it, so a job could be replaced to run arbitrary commands."
		}
		finding.Impact = "A writable cron job file can be replaced to execute arbitrary commands with the scheduler's authority. " +
			"Jobs in system directories typically run as root."
		finding.Remediation = "Restrict write access to cron job files to administrative accounts. " +
			"Review each job for necessity and confirm the executing user."
		finding.Limitations = []string{
			"NULQ reads cron files but does not evaluate @reboot, environment variables or run-parts ordering.",
			"File writability is observed; whether a job is actually executed by cron is not determined.",
			"NULQ never executes discovered jobs or scripts.",
		}
		finding.AddEvidence(
			builder.Add(jobObs, models.AttrCronCommand, "Cron job lines observed from the file."),
			builder.Add(jobObs, models.AttrOwnerUser, "Owner of the cron job file."),
			builder.Add(jobObs, models.AttrWritableByCurrentUser, "Whether the running user could modify the job file."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
