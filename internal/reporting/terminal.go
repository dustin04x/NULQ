package reporting

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/dustin04x/nulq/internal/core/models"
)

// TerminalOptions controls human-readable rendering.
type TerminalOptions struct {
	// Color enables ANSI colour; callers must only enable it for a TTY.
	Color bool
	// Width is the preferred line width. Values below 60 are clamped.
	Width int
	// Quiet hides informational output and findings below MEDIUM.
	Quiet bool
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiGray   = "\x1b[90m"
)

type printer struct {
	out   *bufio.Writer
	color bool
	width int
}

func newPrinter(w io.Writer, opts TerminalOptions) *printer {
	width := opts.Width
	if width <= 0 {
		width = 100
	}
	if width < 60 {
		width = 60
	}
	return &printer{out: bufio.NewWriter(w), color: opts.Color, width: width}
}

func (p *printer) printf(format string, args ...any) {
	fmt.Fprintf(p.out, format, args...)
}

func (p *printer) paint(code, text string) string {
	if !p.color || code == "" {
		return text
	}
	return code + text + ansiReset
}

func (p *printer) severityLabel(severity models.Severity) string {
	label := fmt.Sprintf("%-8s", severity)
	return p.paint(severityColor(severity), label)
}

func severityColor(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "\x1b[1;31m"
	case models.SeverityHigh:
		return ansiRed
	case models.SeverityMedium:
		return ansiYellow
	case models.SeverityLow:
		return ansiBlue
	default:
		return ansiGray
	}
}

// Terminal renders a full scan report for a human reader.
func Terminal(w io.Writer, rep models.Report, opts TerminalOptions) error {
	p := newPrinter(w, opts)
	p.renderReport(rep, opts)
	return p.out.Flush()
}

func (p *printer) renderReport(rep models.Report, opts TerminalOptions) {
	evidenceByID := make(map[string]models.Evidence, len(rep.Evidence))
	for _, item := range rep.Evidence {
		evidenceByID[item.ID] = item
	}

	if !opts.Quiet {
		p.printf("%s %s  %s\n\n", p.paint(ansiBold, "NULQ"), singleLine(rep.Tool.Version),
			p.paint(ansiDim, "Linux privilege-boundary assessment"))
		p.printf("Host      %s\n", singleLine(hostSummary(rep.Host)))
		p.printf("Session   %s\n", singleLine(sessionSummary(rep.Scan)))
		p.printf("Scan      %s · %d rules · %d observations · %s\n",
			rep.Scan.ReportID, rep.Stats.Rules.Total, rep.Stats.Observations, formatDuration(rep.Scan.DurationMS))
		if rep.Scan.Partial {
			p.printf("Coverage  %s\n", p.paint(ansiYellow, "partial: some sources were unavailable, failed or truncated"))
		}
		p.printf("\n")
	}

	counts := rep.FindingCountBySeverity()
	var summary []string
	for _, severity := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		if counts[severity] > 0 {
			summary = append(summary, fmt.Sprintf("%s %d", p.severityLabel(severity), counts[severity]))
		}
	}
	if len(summary) == 0 {
		p.printf("%s\n\n", p.paint(ansiDim, "No findings were produced."))
	} else {
		p.printf("%s\n\n", strings.Join(summary, "  "))
	}

	shown := 0
	for _, finding := range rep.Findings {
		if opts.Quiet && finding.Severity.Rank() < models.SeverityMedium.Rank() {
			continue
		}
		if !opts.Quiet && finding.Severity.Rank() <= models.SeverityLow.Rank() {
			p.printf("%s %s  %s  %s\n",
				p.severityLabel(finding.Severity),
				p.paint(ansiDim, finding.RuleID),
				singleLine(finding.Title),
				p.paint(ansiDim, "("+singleLine(finding.Resource)+")"))
			shown++
			continue
		}
		p.renderFinding(finding, evidenceByID)
		shown++
	}

	if shown == 0 && len(rep.Findings) > 0 {
		p.printf("%s\n\n", p.paint(ansiDim, "All findings are below the MEDIUM severity threshold (quiet mode)."))
	}
	if len(rep.Findings) > 0 {
		p.printf("\n")
	}

	p.printf("%s\n", p.paint(ansiDim, fmt.Sprintf(
		"%d/%d rules executed · %d skipped · %d failed · %d collectors",
		rep.Stats.Rules.Executed, rep.Stats.Rules.Total, rep.Stats.Rules.Skipped, rep.Stats.Rules.Failed,
		len(rep.Stats.Collectors))))
	p.printf("%s\n", p.paint(ansiDim, "Read-only assessment: no system state was modified and no discovered binary was executed."))

	if !opts.Quiet && len(rep.Limitations) > 0 {
		p.printf("\n%s\n", p.paint(ansiDim, "Scope and limitations:"))
		for _, limitation := range rep.Limitations {
			p.printf("  - %s\n", singleLine(limitation))
		}
	}
}

func (p *printer) renderFinding(finding models.Finding, evidenceByID map[string]models.Evidence) {
	p.printf("%s %s  %s\n", p.severityLabel(finding.Severity), finding.RuleID, singleLine(finding.Title))
	p.printf("         %s %s (%s)\n", p.paint(ansiDim, "Resource:"), singleLine(finding.Resource), singleLine(finding.ResourceKind))
	p.printf("         %s %s · rule %s v%s\n",
		p.paint(ansiDim, "Confidence:"), finding.Confidence, finding.RuleID, finding.RuleVersion)
	p.writeParagraph("Why", finding.Explanation)
	p.writeParagraph("Impact", finding.Impact)
	p.writeParagraph("Remediation", finding.Remediation)
	if len(finding.Evidence) > 0 {
		p.printf("         %s\n", p.paint(ansiDim, "Evidence:"))
		for _, id := range finding.Evidence {
			item, ok := evidenceByID[id]
			if !ok {
				continue
			}
			field := item.Field
			if field == "" {
				field = "resource"
			}
			p.printf("           - %s %s=%s [%s]\n",
				singleLine(item.Resource), singleLine(field), singleLine(item.ObservedValue), item.ID)
		}
	}
	if len(finding.Limitations) > 0 {
		p.writeParagraph("Limits", strings.Join(finding.Limitations, " "))
	}
	p.printf("\n")
}

func (p *printer) writeParagraph(label, value string) {
	value = strings.TrimSpace(multiLine(value))
	if value == "" {
		return
	}
	p.printf("         %s\n", p.paint(ansiDim, label+":"))
	for _, line := range wrapText(value, p.width-12) {
		p.printf("           %s\n", line)
	}
}

// SystemInfo renders the `nulq system info` view.
func SystemInfo(w io.Writer, rep models.Report, opts TerminalOptions) error {
	p := newPrinter(w, opts)
	evidence := rep.Observations

	var info models.Observation
	var contextObs models.Observation
	var controls []models.Observation
	var parameters []models.Observation
	for _, obs := range evidence {
		switch obs.Kind {
		case models.KindSystemInfo:
			info = obs
		case models.KindExecutionContext:
			contextObs = obs
		case models.KindSecurityControl:
			controls = append(controls, obs)
		case models.KindSysctl:
			parameters = append(parameters, obs)
		}
	}

	p.printf("%s %s  %s\n\n", p.paint(ansiBold, "NULQ"), singleLine(rep.Tool.Version),
		p.paint(ansiDim, "system information"))

	field := func(label string, obs models.Observation, key string) {
		if value, ok := obs.Attr(key); ok && value != "" {
			p.printf("%-14s %s\n", label, singleLine(value))
		}
	}
	field("Hostname", info, models.AttrHostname)
	field("Distribution", info, models.AttrOSName)
	field("OS ID", info, models.AttrOSID)
	field("OS version", info, models.AttrOSVersion)
	field("Kernel", info, models.AttrKernelRelease)
	field("Architecture", info, models.AttrArchitecture)
	field("Container", info, models.AttrContainer)
	field("Runtime", info, models.AttrContainerRuntime)
	field("Cgroup", info, models.AttrCgroupVersion)
	field("LSM modules", info, models.AttrLSMList)

	if contextObs.ID != "" {
		p.printf("\n%s\n", p.paint(ansiBold, "Execution context"))
		field("User", contextObs, models.AttrUsername)
		field("UID", contextObs, models.AttrUID)
		field("EUID", contextObs, models.AttrEUID)
		field("GID", contextObs, models.AttrGID)
		field("EGID", contextObs, models.AttrEGID)
		field("Groups", contextObs, models.AttrGroups)
		field("Umask", contextObs, models.AttrUmask)
	}

	if len(controls) > 0 {
		p.printf("\n%s\n", p.paint(ansiBold, "Security controls"))
		for _, control := range controls {
			state := "unavailable"
			if control.Status == models.StatusComplete {
				if control.Bool(models.AttrActive) {
					state = "active"
				} else {
					state = "inactive"
				}
				if detail, ok := control.Attr(models.AttrDetail); ok && detail != "" {
					state += " (" + detail + ")"
				}
			} else if control.Error != nil {
				state = "unavailable (" + control.Error.Class + ")"
			}
			p.printf("  %-20s %s\n", singleLine(control.Resource), singleLine(state))
		}
	}

	if len(parameters) > 0 {
		p.printf("\n%s\n", p.paint(ansiBold, "Kernel parameters"))
		for _, parameter := range parameters {
			value := "unavailable"
			if parameter.Status == models.StatusComplete {
				if observed, ok := parameter.Attr(models.AttrValue); ok {
					value = observed
				}
			} else if parameter.Error != nil {
				value = "unavailable (" + parameter.Error.Class + ")"
			}
			p.printf("  %-38s %s\n", singleLine(parameter.Resource), singleLine(value))
		}
	}
	return p.out.Flush()
}

func hostSummary(host models.HostInfo) string {
	name := host.Hostname
	if name == "" {
		name = "unknown-host"
	}
	var parts []string
	if host.OSName != "" {
		parts = append(parts, host.OSName)
	}
	if host.KernelRelease != "" {
		parts = append(parts, "kernel "+host.KernelRelease)
	}
	if host.Architecture != "" {
		parts = append(parts, host.Architecture)
	}
	if len(parts) == 0 {
		return name
	}
	return name + " (" + strings.Join(parts, ", ") + ")"
}

func sessionSummary(scan models.ScanInfo) string {
	privilege := "unprivileged user"
	if !scan.Unprivileged {
		privilege = "elevated user"
	}
	return privilege
}

func formatDuration(milliseconds int64) string {
	if milliseconds < 1000 {
		return fmt.Sprintf("%dms", milliseconds)
	}
	return fmt.Sprintf("%.1fs", float64(milliseconds)/1000)
}

func wrapText(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		current := ""
		for _, word := range strings.Fields(paragraph) {
			switch {
			case current == "":
				current = word
			case len(current)+1+len(word) <= width:
				current += " " + word
			default:
				lines = append(lines, current)
				current = word
			}
		}
		if current != "" {
			lines = append(lines, current)
		}
	}
	return lines
}
