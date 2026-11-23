package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/storage"
)

// writeReportFile writes a report JSON document directly into the storage
// reports directory. It bypasses Store.SaveReport because SaveReport derives
// the filename from the report's ReportID (which rejects the hostile ids used
// to model tampered input); tests must be able to plant such files to exercise
// untrusted-input handling.
func writeReportFile(t *testing.T, dir, filename string, rep models.Report) {
	t.Helper()
	reportsDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, filename+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validReport(reportID string) models.Report {
	return models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool:          models.ToolInfo{Name: "nulq", Version: "test", GoVersion: "go", Platform: "linux/amd64"},
		Scan:          models.ScanInfo{ReportID: reportID, StartedAt: time.Unix(0, 0).UTC()},
		Coverage:      models.Coverage{Status: models.CoverageComplete},
	}
}

// TestReportListSanitizesUntrustedFields verifies that fields read back from a
// stored (and potentially tampered) report cannot inject terminal escape
// sequences into stdout. Storage pins report_id to the filename, so the
// reachable untrusted fields are tool.version and coverage.status; a hostile
// report_id is rejected at load time (covered by the malformed test).
func TestReportListSanitizesUntrustedFields(t *testing.T) {
	dir := t.TempDir()
	rep := validReport("rpt-evil")
	rep.Tool.Version = "nulq\x1b[2J\x1b[31m"
	rep.Coverage.Status = "complete\x07"
	writeReportFile(t, dir, "rpt-evil", rep)

	app, stdout, _ := newTestApp()
	code := app.Run(context.Background(), []string{"report", "list", "--data-dir", dir})
	if code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	out := stdout.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Fatalf("report list leaked ESC to stdout: %q", out)
	}
	if strings.ContainsRune(out, '\x07') {
		t.Fatalf("report list leaked BEL to stdout: %q", out)
	}
	if !strings.Contains(out, "findings=") {
		t.Fatalf("report list produced no report line: %q", out)
	}
}

// TestReportListToleratesMalformedAndOrdersDeterministically verifies that one
// corrupt report file does not abort the listing and that the remaining reports
// are printed in a stable, sorted order.
func TestReportListToleratesMalformedAndOrdersDeterministically(t *testing.T) {
	dir := t.TempDir()
	writeReportFile(t, dir, "rpt-c", validReport("rpt-c"))
	writeReportFile(t, dir, "rpt-a", validReport("rpt-a"))
	writeReportFile(t, dir, "rpt-b", validReport("rpt-b"))

	// Plant a corrupt document with a valid filename.
	reportsDir := filepath.Join(dir, "reports")
	if err := os.WriteFile(filepath.Join(reportsDir, "rpt-bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"report", "list", "--data-dir", dir}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "unreadable") {
		t.Fatalf("corrupt report should be reported as unreadable, got: %q", out)
	}

	// Run again and confirm the ordering of the readable report ids is stable.
	app2, stdout2, _ := newTestApp()
	_ = app2.Run(context.Background(), []string{"report", "list", "--data-dir", dir})
	if stdout2.String() != out {
		t.Fatalf("report list is not deterministic:\nfirst:\n%s\nsecond:\n%s", out, stdout2.String())
	}
	aIdx := strings.Index(out, "rpt-a")
	bIdx := strings.Index(out, "rpt-b")
	cIdx := strings.Index(out, "rpt-c")
	badIdx := strings.Index(out, "rpt-bad")
	if !(aIdx < bIdx && bIdx < cIdx) {
		t.Fatalf("readable reports not in sorted order: %q", out)
	}
	if badIdx >= 0 && badIdx < aIdx {
		t.Fatalf("unexpected ordering with corrupt entry: %q", out)
	}
}

// TestReportShowMalformedReturnsError verifies a corrupt report file yields a
// runtime error (exit 1), never a panic.
func TestReportShowMalformedReturnsError(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, "rpt-bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"report", "show", "--data-dir", dir, "rpt-bad"}); code != ExitError {
		t.Fatalf("exit code = %d, want %d", code, ExitError)
	}
}

// TestReportExportRejectsUnknownFormat verifies export validates the format
// before touching storage.
func TestReportExportRejectsUnknownFormat(t *testing.T) {
	app, _, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"report", "export", "rpt-x", "--format", "xml"}); code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
}

// TestReportAndBaselineSubcommandValidation pins the argument-handling contract
// for missing and unknown subcommands and for a flag missing its value.
func TestReportAndBaselineSubcommandValidation(t *testing.T) {
	cases := [][]string{
		{"report"},
		{"report", "bogus"},
		{"report", "show"}, // missing id
		{"report", "show", "--data-dir", t.TempDir()}, // --data-dir consumes the only value, no id left
		{"baseline"},
		{"baseline", "bogus"},
		{"baseline", "show"},
	}
	for _, args := range cases {
		app, _, _ := newTestApp()
		if code := app.Run(context.Background(), args); code != ExitUsage {
			t.Errorf("args %v: exit code = %d, want %d", args, code, ExitUsage)
		}
	}
}

// TestBaselineListSanitizesUntrustedFields verifies baseline fields loaded from
// disk cannot inject terminal escapes into stdout.
func TestBaselineListSanitizesUntrustedFields(t *testing.T) {
	dir := t.TempDir()
	baselinesDir := filepath.Join(dir, "baselines")
	if err := os.MkdirAll(baselinesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := storage.Baseline{
		Name:      "evil\x1b[31mbaseline",
		ReportID:  "rpt-\x1b[2J",
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baselinesDir, "evil.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"baseline", "list", "--data-dir", dir}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	out := stdout.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Fatalf("baseline list leaked ESC to stdout: %q", out)
	}
}

// TestReportListEmpty verifies the empty-store message and success exit.
func TestReportListEmpty(t *testing.T) {
	dir := t.TempDir()
	app, stdout, _ := newTestApp()
	if code := app.Run(context.Background(), []string{"report", "list", "--data-dir", dir}); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("No saved reports.")) {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
}
