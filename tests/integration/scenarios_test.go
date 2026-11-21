package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/app"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/version"
	"github.com/dustin04x/nulq/pkg/api"
)

func scanConfig(root, pathEnv string) app.ScanConfig {
	return app.ScanConfig{
		Modules:          []string{"filesystem"},
		Concurrency:      2,
		RuleTimeout:      10 * time.Second,
		CollectorTimeout: 30 * time.Second,
		ScanRoots:        []string{root},
		PathEnv:          pathEnv,
		MaxFiles:         5000,
		Tool:             version.Info{Version: "test", GoVersion: "go-test", Platform: "linux/amd64"},
	}
}

func writeFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func makeDir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestScenarioPrivilegedLocations covers the synthetic equivalent of a host
// with a set-owner-ID binary and a world-writable directory.
func TestScenarioPrivilegedLocations(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "privtool"), 0o755|fs.ModeSetuid)
	makeDir(t, filepath.Join(root, "srv", "shared"), 0o777)

	report, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}

	rules := map[string]int{}
	for _, finding := range report.Findings {
		rules[finding.RuleID]++
		if err := finding.Validate(); err != nil {
			t.Fatalf("invalid finding %s: %v", finding.ID, err)
		}
	}
	if rules["NULQ-FS-001"] != 1 {
		t.Fatalf("expected one SUID finding, got %d", rules["NULQ-FS-001"])
	}
	if rules["NULQ-FS-002"] != 1 {
		t.Fatalf("expected one world-writable finding, got %d", rules["NULQ-FS-002"])
	}
	if report.Scan.Partial {
		t.Fatal("a complete fixture should not be reported as partial")
	}
}

// TestScenarioSafeSymlinkPath ensures the /bin-style symlink regression stays
// fixed end-to-end: a PATH entry that is a symlink to a root-like directory
// must not be reported as writable.
func TestScenarioSafeSymlinkPath(t *testing.T) {
	root := t.TempDir()
	safe := filepath.Join(root, "usr", "local", "libexec")
	makeDir(t, safe, 0o555)
	link := filepath.Join(root, "bin")
	if err := os.Symlink(safe, link); err != nil {
		t.Fatal(err)
	}

	report, err := app.Scan(context.Background(), scanConfig(root, link), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "NULQ-FS-003" {
			t.Fatalf("safe symlinked PATH entry produced a finding: %s", finding.Explanation)
		}
	}
}

// TestScenarioTruncatedCoverage verifies that exhausted traversal budgets are
// visible to consumers rather than silently dropping findings.
func TestScenarioTruncatedCoverage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "privtool"), 0o755|fs.ModeSetuid)

	cfg := scanConfig(root, "")
	cfg.MaxFiles = 1

	report, err := app.Scan(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Scan.Partial {
		t.Fatal("truncated scan must report partial coverage")
	}
	found := false
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "truncated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations must mention truncation: %v", report.Limitations)
	}
}

// TestScenarioAPICompatibility verifies that the public package can decode the
// exact JSON the CLI emits, with evidence intact.
func TestScenarioAPICompatibility(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "privtool"), 0o755|fs.ModeSetuid)

	report, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := api.ParseReport(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != api.SchemaVersion {
		t.Fatalf("schema version = %q", decoded.SchemaVersion)
	}
	if len(decoded.Findings) != len(report.Findings) {
		t.Fatalf("findings lost in round trip: %d != %d", len(decoded.Findings), len(report.Findings))
	}

	evidenceIDs := map[string]struct{}{}
	for _, item := range decoded.Evidence {
		evidenceIDs[item.ID] = struct{}{}
	}
	for _, finding := range decoded.Findings {
		for _, id := range finding.Evidence {
			if _, ok := evidenceIDs[id]; !ok {
				t.Fatalf("decoded finding %s cites missing evidence %s", finding.ID, id)
			}
		}
	}

	// Observations are opt-in for scans; only system info includes them.
	if decoded.Observations != nil {
		t.Fatal("scan reports must omit observations unless requested")
	}

	cfg := scanConfig(root, "")
	cfg.IncludeObservations = true
	withObservations, err := app.Scan(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(withObservations.Observations) == 0 {
		t.Fatal("requested observations must be present")
	}
}

// TestScenarioDeterministicOrdering checks that repeated scans of unchanged
// fixture state produce the same finding order.
func TestScenarioDeterministicOrdering(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "a"), 0o755|fs.ModeSetuid)
	writeFile(t, filepath.Join(root, "opt", "b"), 0o755|fs.ModeSetuid)
	makeDir(t, filepath.Join(root, "shared"), 0o777)

	first, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("finding counts differ: %d != %d", len(first.Findings), len(second.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].ID != second.Findings[i].ID {
			t.Fatalf("finding order is not deterministic at index %d", i)
		}
	}
}

// TestScenarioUnknownModuleFailsLoudly ensures rule selection never silently
// narrows a scan.
func TestScenarioUnknownModuleFailsLoudly(t *testing.T) {
	cfg := scanConfig(t.TempDir(), "")
	cfg.Modules = []string{"filesystem", "does-not-exist"}
	if _, err := app.Scan(context.Background(), cfg, nil); err == nil {
		t.Fatal("unknown modules must be rejected")
	}
}

// TestScenarioModelInvariants asserts report-level invariants consumers rely
// on, independent of the fixture contents.
func TestScenarioModelInvariants(t *testing.T) {
	report, err := app.Scan(context.Background(), scanConfig(t.TempDir(), ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != models.SchemaVersion {
		t.Fatalf("schema version = %q", report.SchemaVersion)
	}
	if report.Tool.Name != "nulq" {
		t.Fatalf("tool name = %q", report.Tool.Name)
	}
	if report.Scan.ReportID == "" || report.Scan.FinishedAt.Before(report.Scan.StartedAt) {
		t.Fatal("scan metadata is inconsistent")
	}
	if report.Stats.Observations == 0 {
		t.Fatal("collectors must produce observations")
	}
	if len(report.Limitations) == 0 {
		t.Fatal("reports must state their limitations")
	}
}
