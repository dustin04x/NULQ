package lab

import (
	"fmt"
	"strings"
)

// RenderSummary produces the Markdown laboratory report. It states every
// category the laboratory distinguishes, including unsupported scenarios and
// collection failures, so the document cannot read as more complete than the
// run actually was.
func RenderSummary(result Result) string {
	var b strings.Builder

	b.WriteString("# NULQ laboratory validation\n\n")
	verdict := "FAIL"
	if result.Summary.Passed {
		verdict = "PASS"
	}
	fmt.Fprintf(&b, "**Verdict:** %s\n\n", verdict)
	fmt.Fprintf(&b, "Generated: %s\n\n", md(result.GeneratedAt))

	b.WriteString("## Environment\n\n| Field | Value |\n|---|---|\n")
	rows := [][2]string{
		{"Target", result.Environment.Target},
		{"Image", result.Environment.Image},
		{"Image ID", result.Environment.ImageID},
		{"Base image", result.Environment.BaseImage},
		{"Base digest", result.Environment.BaseDigest},
		{"NULQ version", result.Environment.NulqVersion},
		{"Image built at", result.Environment.BuiltAt},
		{"Container uid", fmt.Sprintf("%d", result.Environment.ContainerUID)},
	}
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s |\n", row[0], md(row[1]))
	}

	b.WriteString("\n## Summary\n\n| Metric | Value |\n|---|---|\n")
	summaryRows := [][2]string{
		{"Scenarios total", fmt.Sprintf("%d", result.Summary.ScenariosTotal)},
		{"Passed", fmt.Sprintf("%d", result.Summary.ScenariosPassed)},
		{"Failed", fmt.Sprintf("%d", result.Summary.ScenariosFailed)},
		{"Unsupported", fmt.Sprintf("%d", result.Summary.ScenariosUnsupported)},
		{"Expected findings", fmt.Sprintf("%d", result.Summary.ExpectedFindings)},
		{"Actual findings", fmt.Sprintf("%d", result.Summary.ActualFindings)},
		{"Missing findings", fmt.Sprintf("%d", result.Summary.MissingFindings)},
		{"Unexpected findings", fmt.Sprintf("%d", result.Summary.UnexpectedFindings)},
		{"Severity mismatches", fmt.Sprintf("%d", result.Summary.SeverityMismatches)},
		{"Confidence mismatches", fmt.Sprintf("%d", result.Summary.ConfidenceMismatches)},
		{"Scans validated", fmt.Sprintf("%d", result.Summary.ScansValidated)},
		{"Scans invalid", fmt.Sprintf("%d", result.Summary.ScansInvalid)},
	}
	for _, row := range summaryRows {
		fmt.Fprintf(&b, "| %s | %s |\n", row[0], row[1])
	}

	b.WriteString("\n## Container isolation\n\n| Check | Result | Detail |\n|---|---|---|\n")
	for _, check := range result.Isolation.Checks {
		state := "PASS"
		if !check.Passed {
			state = "FAIL"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", md(check.Description), state, md(check.Detail))
	}

	b.WriteString("\n## Scenarios\n\n| ID | Category | Environment | Scan | Status | Findings |\n|---|---|---|---|---|---|\n")
	for _, scenario := range result.Scenarios {
		scan := scenario.Scan
		if scan == "" {
			scan = "—"
		}
		status := strings.ToUpper(scenario.Status)
		if scenario.Status == "unsupported" {
			status = "UNSUPPORTED"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d |\n",
			md(scenario.ID), md(scenario.Category), md(scenario.Environment), md(scan), status, scenario.Findings)
	}

	if len(result.Findings.ByRule) > 0 {
		b.WriteString("\n## Findings by rule\n\n| Rule | Findings |\n|---|---|\n")
		for _, tally := range result.Findings.ByRule {
			fmt.Fprintf(&b, "| %s | %d |\n", md(tally.RuleID), tally.Count)
		}
	}

	writeFindingRefs := func(title string, refs []FindingRef) {
		if len(refs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Scenario | Rule | Resource | Severity |\n|---|---|---|---|\n", title)
		for _, ref := range refs {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", md(ref.Scenario), md(ref.RuleID), md(ref.Resource), md(ref.Severity))
		}
	}
	writeFindingRefs("Missing findings", result.Findings.Missing)
	writeFindingRefs("Unexpected findings", result.Findings.Unexpected)

	writeMismatches := func(title string, mismatches []Mismatch) {
		if len(mismatches) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Scenario | Rule | Resource | Expected | Actual |\n|---|---|---|---|---|\n", title)
		for _, mismatch := range mismatches {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				md(mismatch.Scenario), md(mismatch.RuleID), md(mismatch.Resource),
				md(mismatch.Expected), md(mismatch.Actual))
		}
	}
	writeMismatches("Severity mismatches", result.Findings.SeverityMismatches)
	writeMismatches("Confidence mismatches", result.Findings.ConfidenceMismatches)

	b.WriteString("\n## Coverage\n\n| Scan | Status | Execution complete | Coverage complete | Files | Directories | Errors | Denied | Truncated roots |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, scan := range result.Coverage {
		truncated := "—"
		if len(scan.TruncatedRoots) > 0 {
			truncated = strings.Join(scan.TruncatedRoots, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %t | %t | %d | %d | %d | %d | %s |\n",
			md(scan.Scan), md(scan.Status), scan.ExecutionComplete, scan.CoverageComplete,
			scan.FilesExamined, scan.DirectoriesExamined, scan.TraversalErrors,
			scan.PermissionDenied, md(truncated))
	}

	b.WriteString("\n## Scans\n\n| Scan | Report | OS | Duration | Observations | Findings | Schema |\n|---|---|---|---|---|---|---|\n")
	for _, scan := range result.Scans {
		schema := "valid"
		if !scan.SchemaValid {
			schema = "INVALID"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d ms | %d | %d | %s |\n",
			md(scan.Name), md(scan.Artifact), md(scan.OSID), scan.DurationMS,
			scan.Observations, scan.Findings, schema)
		if len(scan.SchemaErrors) > 0 {
			for _, problem := range scan.SchemaErrors {
				fmt.Fprintf(&b, "\n- **%s schema error:** %s\n", md(scan.Name), md(problem))
			}
		}
	}

	if len(result.CollectionErrors) > 0 {
		b.WriteString("\n## Collection errors\n\n")
		for _, message := range result.CollectionErrors {
			fmt.Fprintf(&b, "- %s\n", md(message))
		}
	}

	if len(result.Scenarios) > 0 {
		var unsupported []ScenarioResult
		for _, scenario := range result.Scenarios {
			if scenario.Status == "unsupported" {
				unsupported = append(unsupported, scenario)
			}
		}
		if len(unsupported) > 0 {
			b.WriteString("\n## Unsupported checks\n\n")
			for _, scenario := range unsupported {
				fmt.Fprintf(&b, "- **%s** (%s): %s\n", md(scenario.ID), md(scenario.Title), md(scenario.Reason))
			}
		}
	}

	b.WriteString("\n## Limitations\n\n")
	for _, limitation := range result.Limitations {
		fmt.Fprintf(&b, "- %s\n", md(limitation))
	}

	b.WriteString("\n## Artifacts\n\n")
	b.WriteString("- `scan.json` — baseline Alpine assessment\n")
	b.WriteString("- `scan-fixtures.json` — fixture-root assessment\n")
	b.WriteString("- `scan-path.json` — hostile PATH assessment\n")
	b.WriteString("- `scan-identity.json` — wheel-membership assessment\n")
	b.WriteString("- `isolation.json` — in-container security probe\n")
	b.WriteString("- `validation.json` — machine-readable validation result\n")

	return b.String()
}

// md keeps free text inside a Markdown table cell.
func md(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ")
	return replacer.Replace(value)
}
