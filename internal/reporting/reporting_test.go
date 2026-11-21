package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

func sampleReport() models.Report {
	meta := models.RuleMetadata{
		ID: "NULQ-T-001", Version: "1.0.0", Name: "Test rule", Description: "Test description",
		Category: "test", Module: "test", Severity: models.SeverityHigh,
		Confidence: models.ConfidenceHigh, Required: []models.Kind{models.KindFile},
		Platforms: []string{"linux"},
	}
	resource := "/tmp/evil\x1b[31mname"
	obs := models.NewObservation(models.KindFile, resource, "test", time.Now(), map[string]string{
		models.AttrMode: "0777",
	})
	builder := evidence.New()
	evidenceID := builder.Add(obs, models.AttrMode, "Observed mode")
	finding := models.NewFinding(meta, resource, models.ResourceFile, models.SeverityHigh, models.ConfidenceHigh, "Test finding", time.Now())
	finding.Explanation = "The observed mode allows any user to modify the file."
	finding.Impact = "A local user can influence privileged behaviour."
	finding.Remediation = "Restore restrictive ownership and modes."
	finding.AddEvidence(evidenceID)

	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	report := models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool: models.ToolInfo{
			Name: "nulq", Version: "test", GoVersion: "go-test", Platform: "linux/amd64",
		},
		Host: models.HostInfo{
			Hostname: "fixture", Architecture: "amd64", SecurityModules: []string{"capability"},
		},
		Scan: models.ScanInfo{
			ReportID: "rpt-000000000000", StartedAt: started, FinishedAt: started.Add(time.Second),
			DurationMS: 1000, Modules: []string{"test"}, Unprivileged: true,
		},
		Findings: []models.Finding{finding},
		Evidence: builder.Items(),
		Stats: models.Stats{
			Observations: 1, Findings: 1, Evidence: 1,
			Rules: models.RuleStats{Total: 1, Executed: 1},
		},
		Limitations: []string{"Test limitation."},
	}
	report.Normalize()
	return report
}

func TestJSONIsMachineReadableAndVersioned(t *testing.T) {
	var buffer bytes.Buffer
	if err := JSON(&buffer, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buffer.String(), "\x1b[") {
		t.Fatal("JSON output must not contain terminal escape sequences")
	}

	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded["schema_version"] != models.SchemaVersion {
		t.Fatalf("schema_version = %v", decoded["schema_version"])
	}
	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings must be a non-null array, got %T", decoded["findings"])
	}
	if _, ok := decoded["evidence"].([]any); !ok {
		t.Fatal("evidence must be a non-null array")
	}
}

func TestJSONLEmitsOneObjectPerLine(t *testing.T) {
	var buffer bytes.Buffer
	if err := JSONL(&buffer, sampleReport()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected several JSONL records, got %d", len(lines))
	}
	types := make([]string, 0, len(lines))
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		types = append(types, record["type"].(string))
	}
	if types[0] != "scan" || types[len(types)-1] != "summary" {
		t.Fatalf("unexpected JSONL envelope: %v", types)
	}
}

func TestTerminalStripsInjectedEscapesAndShowsRemediation(t *testing.T) {
	var buffer bytes.Buffer
	if err := Terminal(&buffer, sampleReport(), TerminalOptions{Color: false, Width: 100}); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if strings.Contains(output, "\x1b") {
		t.Fatal("terminal output must not contain escape sequences when colour is disabled")
	}
	if !strings.Contains(output, "Remediation") {
		t.Fatal("terminal output should explain remediation")
	}
	if !strings.Contains(output, "NULQ-T-001") {
		t.Fatal("terminal output should identify the rule")
	}
}

func TestMarkdownIncludesFindingsAndLimitations(t *testing.T) {
	var buffer bytes.Buffer
	if err := Markdown(&buffer, sampleReport()); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	for _, want := range []string{"## Findings", "NULQ-T-001", "Scope and limitations", "Test limitation."} {
		if !strings.Contains(output, want) {
			t.Fatalf("markdown output is missing %q", want)
		}
	}
	if strings.Contains(output, "\x1b") {
		t.Fatal("markdown output must not contain escape sequences")
	}
}

func TestQuietTerminalHidesLowSeverity(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Severity = models.SeverityLow
	report.Normalize()

	var buffer bytes.Buffer
	if err := Terminal(&buffer, report, TerminalOptions{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buffer.String(), "Test finding") {
		t.Fatal("quiet mode must not print LOW findings")
	}
}
