package lab

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

func validReport() models.Report {
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	report := models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool: models.ToolInfo{
			Name: "nulq", Version: "test", GoVersion: "go-test", Platform: "linux/amd64",
		},
		Host: models.HostInfo{Hostname: "lab", Architecture: "amd64"},
		Scan: models.ScanInfo{
			ReportID: "rpt-0123456789ab", StartedAt: started, FinishedAt: started.Add(time.Second),
			DurationMS: 1000, Unprivileged: true,
		},
		Findings:    []models.Finding{},
		Evidence:    []models.Evidence{},
		Stats:       models.Stats{Collectors: []models.CollectorStatus{}},
		Coverage:    models.Coverage{Status: models.CoverageComplete, ExecutionComplete: true, CoverageComplete: true},
		Limitations: []string{"fixture"},
	}
	report.Normalize()
	return report
}

func decode(t *testing.T, value any) any {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestSchemaAcceptsValidReport(t *testing.T) {
	schema, err := LoadSchema("../../schemas/nulq-report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if problems := schema.Validate(decode(t, validReport())); len(problems) > 0 {
		t.Fatalf("valid report rejected: %v", problems)
	}
}

func TestSchemaRejectsUnknownProperty(t *testing.T) {
	schema, err := LoadSchema("../../schemas/nulq-report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, validReport()).(map[string]any)
	document["unexpected"] = true
	problems := schema.Validate(document)
	if len(problems) == 0 || !strings.Contains(problems[0], "unexpected property") {
		t.Fatalf("unknown property was not rejected: %v", problems)
	}
}

func TestSchemaRejectsInvalidCoverageStatus(t *testing.T) {
	schema, err := LoadSchema("../../schemas/nulq-report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, validReport()).(map[string]any)
	coverage := document["coverage"].(map[string]any)
	coverage["status"] = "maybe"
	problems := schema.Validate(document)
	if len(problems) == 0 {
		t.Fatal("invalid coverage status was accepted")
	}
	if !strings.Contains(strings.Join(problems, " "), "not one of") {
		t.Fatalf("unexpected schema errors: %v", problems)
	}
}

func TestSchemaRejectsBadReportID(t *testing.T) {
	schema, err := LoadSchema("../../schemas/nulq-report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document := decode(t, validReport()).(map[string]any)
	document["scan"].(map[string]any)["report_id"] = "report-1"
	problems := schema.Validate(document)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, " "), "does not match") {
		t.Fatalf("malformed report id was accepted: %v", problems)
	}
}
