package reporting

import (
	"fmt"
	"io"
	"strings"

	"github.com/dustin04x/nulq/internal/core/models"
)

// Markdown renders a self-contained report suitable for tickets, reviews and
// archived assessments.
func Markdown(w io.Writer, rep models.Report) error {
	rep.Normalize()
	var b strings.Builder

	b.WriteString("# NULQ security assessment\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	row := func(name, value string) {
		fmt.Fprintf(&b, "| %s | %s |\n", name, markdownSafe(value))
	}
	row("Report", rep.Scan.ReportID)
	row("Schema version", rep.SchemaVersion)
	row("Tool", rep.Tool.Name+" "+rep.Tool.Version)
	row("Host", hostSummary(rep.Host))
	row("Kernel", rep.Host.KernelRelease)
	row("Architecture", rep.Host.Architecture)
	row("Container", boolText(rep.Host.Container))
	row("Started", rep.Scan.StartedAt.Format("2006-01-02T15:04:05Z07:00"))
	row("Duration", formatDuration(rep.Scan.DurationMS))
	row("Modules", strings.Join(rep.Scan.Modules, ", "))
	row("Coverage", coverageText(rep.Scan.Partial))

	counts := rep.FindingCountBySeverity()
	b.WriteString("\n## Summary\n\n| Severity | Findings |\n|---|---|\n")
	for _, severity := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		fmt.Fprintf(&b, "| %s | %d |\n", severity, counts[severity])
	}
	fmt.Fprintf(&b, "| **Total** | **%d** |\n", len(rep.Findings))

	b.WriteString("\n## Findings\n\n")
	if len(rep.Findings) == 0 {
		b.WriteString("_No findings were produced. Absence of findings is not evidence that the system is secure._\n")
	}
	evidenceByID := make(map[string]models.Evidence, len(rep.Evidence))
	for _, item := range rep.Evidence {
		evidenceByID[item.ID] = item
	}

	for index, finding := range rep.Findings {
		fmt.Fprintf(&b, "### %d. [%s] %s\n\n", index+1, finding.Severity, markdownSafe(finding.Title))
		fmt.Fprintf(&b, "- **Rule:** `%s` version `%s`\n", finding.RuleID, finding.RuleVersion)
		fmt.Fprintf(&b, "- **Confidence:** %s\n", finding.Confidence)
		fmt.Fprintf(&b, "- **Resource:** `%s` (%s)\n", markdownSafe(finding.Resource), markdownSafe(finding.ResourceKind))
		fmt.Fprintf(&b, "- **Category:** %s\n", markdownSafe(finding.Category))
		fmt.Fprintf(&b, "- **Detected:** %s\n\n", finding.DetectedAt.Format("2006-01-02T15:04:05Z07:00"))

		fmt.Fprintf(&b, "%s\n\n", markdownSafe(finding.Description))
		fmt.Fprintf(&b, "**Technical explanation.** %s\n\n", markdownSafe(finding.Explanation))
		fmt.Fprintf(&b, "**Potential impact.** %s\n\n", markdownSafe(finding.Impact))
		fmt.Fprintf(&b, "**Remediation.** %s\n\n", markdownSafe(finding.Remediation))

		if len(finding.Evidence) > 0 {
			b.WriteString("**Evidence**\n\n| Evidence | Resource | Field | Observed value |\n|---|---|---|---|\n")
			for _, id := range finding.Evidence {
				item, ok := evidenceByID[id]
				if !ok {
					continue
				}
				field := item.Field
				if field == "" {
					field = "resource"
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` |\n",
					item.ID, markdownSafe(item.Resource), markdownSafe(field), markdownSafe(item.ObservedValue))
			}
			b.WriteString("\n")
		}
		if len(finding.Limitations) > 0 {
			b.WriteString("**Limitations**\n\n")
			for _, limitation := range finding.Limitations {
				fmt.Fprintf(&b, "- %s\n", markdownSafe(limitation))
			}
			b.WriteString("\n")
		}
		if len(finding.References) > 0 {
			b.WriteString("**References**\n\n")
			for _, reference := range finding.References {
				fmt.Fprintf(&b, "- [%s](%s)\n", markdownSafe(reference.Title), reference.URL)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## Scope and limitations\n\n")
	for _, limitation := range rep.Limitations {
		fmt.Fprintf(&b, "- %s\n", markdownSafe(limitation))
	}
	b.WriteString("\nNULQ is read-only: it never modifies the assessed system and never executes discovered binaries or services.\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func boolText(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func coverageText(partial bool) string {
	if partial {
		return "partial"
	}
	return "complete"
}
