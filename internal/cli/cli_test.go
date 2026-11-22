package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/version"
)

func newTestApp() (*App, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return &App{
		Stdout: stdout,
		Stderr: stderr,
		Getenv: os.Getenv,
		Version: version.Info{
			Version: "test-version", Commit: "test-commit", BuildDate: "test-date",
			GoVersion: "go-test", Platform: "linux/amd64",
		},
	}, stdout, stderr
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	suid := filepath.Join(root, "usr", "bin", "privtool")
	if err := os.MkdirAll(filepath.Dir(suid), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suid, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0o755|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	shared := filepath.Join(root, "data")
	if err := os.MkdirAll(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestVersionCommand(t *testing.T) {
	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"version"}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("nulq test-version")) {
		t.Fatalf("unexpected version output: %s", stdout.String())
	}

	app, stdout, _ = newTestApp()
	if code := app.Run(context.Background(), []string{"version", "--format", "json"}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("version JSON is invalid: %v", err)
	}
	if payload["name"] != "nulq" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestRulesListCommand(t *testing.T) {
	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"rules", "list", "--format", "json"}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var rules []models.RuleMetadata
	if err := json.Unmarshal(stdout.Bytes(), &rules); err != nil {
		t.Fatalf("rules JSON is invalid: %v", err)
	}
	if len(rules) != 20 {
		t.Fatalf("want 20 registered rules, got %d", len(rules))
	}
	registered := map[string]models.RuleMetadata{}
	for _, rule := range rules {
		if rule.ID == "" || rule.Module == "" || rule.Name == "" {
			t.Fatalf("incomplete rule metadata: %+v", rule)
		}
		registered[rule.ID] = rule
	}
	// Registration is a separate integration point: a rule that exists in the
	// source but is never constructed is unreachable from every command. Pin
	// the process rule's presence and its required observation kind here.
	process, ok := registered["NULQ-PROC-001"]
	if !ok {
		t.Fatal("NULQ-PROC-001 is not registered")
	}
	if len(process.Required) != 1 || process.Required[0] != models.KindProcess {
		t.Fatalf("NULQ-PROC-001 required observations = %v, want [process]", process.Required)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"scan", "--bogus-flag"},
		{"scan", "--modules", "nope"},
		{"scan", "--format", "xml"},
		{"rules", "list", "--module", "nope"},
		{"system", "info", "--format", "yaml"},
	}
	for _, args := range cases {
		app, _, _ := newTestApp()
		if code := app.Run(context.Background(), args); code != ExitUsage {
			t.Errorf("args %v: exit code = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestScanFixtureProducesConsumableJSON(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("NO_COLOR", "1")

	root := fixtureRoot(t)
	app, stdout, stderr := newTestApp()
	code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json", "--modules", "filesystem",
	})
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}

	var report models.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("scan output is not a valid report: %v\n%s", err, stdout.String())
	}
	if report.SchemaVersion != models.SchemaVersion {
		t.Fatalf("schema_version = %q", report.SchemaVersion)
	}
	if len(report.Findings) < 2 {
		t.Fatalf("expected at least 2 findings from the fixture, got %d", len(report.Findings))
	}
	evidenceIDs := make(map[string]struct{}, len(report.Evidence))
	for _, item := range report.Evidence {
		evidenceIDs[item.ID] = struct{}{}
	}
	for _, finding := range report.Findings {
		if len(finding.Evidence) == 0 {
			t.Fatalf("finding %s cites no evidence", finding.ID)
		}
		for _, id := range finding.Evidence {
			if _, ok := evidenceIDs[id]; !ok {
				t.Fatalf("finding %s cites dangling evidence %s", finding.ID, id)
			}
		}
	}
}

func TestScanFailOnContract(t *testing.T) {
	t.Setenv("PATH", "")
	root := fixtureRoot(t)

	app, _, _ := newTestApp()
	if code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json", "--fail-on", "medium",
	}); code != ExitFindings {
		t.Fatalf("fail-on medium: exit code = %d, want %d", code, ExitFindings)
	}

	app, _, _ = newTestApp()
	if code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json", "--fail-on", "high",
	}); code != ExitOK {
		t.Fatalf("fail-on high: exit code = %d, want %d", code, ExitOK)
	}
}

// testFailOnContractCoverages codifies the fail-on severity contract:
//   - A finding at or above the threshold triggers exit 3.
//   - Findings below the threshold result in exit 0.
//   - No findings result in exit 0 regardless of threshold.
func testFailOnContractCoverages(t *testing.T, threshold string, expectExit int) {
	t.Helper()
	root := fixtureRoot(t)

	app, _, _ := newTestApp()
	code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json",
		"--fail-on", threshold,
	})
	if code != expectExit {
		t.Fatalf("fail-on %s: exit code = %d, want %d", threshold, code, expectExit)
	}
}

// Verify the documented contract: exit 3 when a finding at or above the threshold exists.
func TestScanFailOnContractCoverages(t *testing.T) {
	// The fixture produces max severity MEDIUM, so:
	testFailOnContractCoverages(t, "info", ExitFindings)   // MEDIUM >= INFO => 3
	testFailOnContractCoverages(t, "low", ExitFindings)    // MEDIUM >= LOW => 3
	testFailOnContractCoverages(t, "medium", ExitFindings) // MEDIUM >= MEDIUM => 3
	testFailOnContractCoverages(t, "high", ExitOK)         // MEDIUM >= HIGH => 0
	testFailOnContractCoverages(t, "critical", ExitOK)     // MEDIUM >= CRITICAL => 0
}

// verifyNoFindingsWithFailOn ensures that a scan with no findings
// always returns exit 0, regardless of the --fail-on threshold.
func TestScanFailOnNoFindings(t *testing.T) {
	t.Setenv("PATH", "")
	// Use a minimal empty root instead of fixtureRoot to avoid producing findings
	root := t.TempDir()

	app, _, _ := newTestApp()
	code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json",
		"--fail-on", "high",
	})
	// With no findings, MaxSeverity() returns "" (invalid), AtLeast returns false => exit 0
	if code != ExitOK {
		t.Fatalf("fail-on high with no findings: exit code = %d, want %d", code, ExitOK)
	}
}

func TestScanBudgetProducesPartialReport(t *testing.T) {
	t.Setenv("PATH", "")
	root := fixtureRoot(t)

	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{
		"scan", "--root", root, "--format", "json", "--max-files", "1",
	}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	var report models.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Scan.Partial {
		t.Fatal("a truncated scan must report partial coverage")
	}
}

func TestScanRejectsUnknownRule(t *testing.T) {
	app, _, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"scan", "--rules", "NULQ-NOPE-999"}); code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
}
