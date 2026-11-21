package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dustin04x/nulq/internal/app"
	"github.com/dustin04x/nulq/internal/core/models"
)

// TestCoveragePermissionDenied verifies that a subtree the scan cannot enter is
// reported as partial coverage with an explicit permission-denied count. A
// scan that ran every rule must still not claim complete coverage.
func TestCoveragePermissionDenied(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "restricted")
	makeDir(t, denied, 0o755)
	writeFile(t, filepath.Join(denied, "secret"), 0o600)
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore access so temporary-directory cleanup can remove the tree.
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	report, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}

	if !report.Coverage.ExecutionComplete {
		t.Fatalf("collectors and rules completed; execution_complete must be true: %+v", report.Coverage)
	}
	if report.Coverage.CoverageComplete {
		t.Fatal("an unreadable subtree must not be reported as complete coverage")
	}
	if report.Coverage.Status != models.CoveragePartial {
		t.Fatalf("coverage status = %q, want %q", report.Coverage.Status, models.CoveragePartial)
	}
	if report.Coverage.PermissionDenied < 1 {
		t.Fatalf("permission_denied = %d, want at least 1", report.Coverage.PermissionDenied)
	}
	if report.Coverage.TraversalErrors < report.Coverage.PermissionDenied {
		t.Fatalf("traversal errors (%d) must include denials (%d)",
			report.Coverage.TraversalErrors, report.Coverage.PermissionDenied)
	}
	if len(report.Coverage.Roots) != 1 || report.Coverage.Roots[0].Root != root {
		t.Fatalf("coverage roots = %+v, want one entry for %s", report.Coverage.Roots, root)
	}
	if report.Coverage.Roots[0].Status != models.CoveragePartial {
		t.Fatalf("root status = %q, want partial", report.Coverage.Roots[0].Status)
	}
}

// TestCoverageBudgetTruncation verifies that exhaustion of the traversal budget
// is attributed to the specific root and never reported as a complete scan.
func TestCoverageBudgetTruncation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "b", "c", "file"), 0o600)

	cfg := scanConfig(root, "")
	cfg.MaxFiles = 2

	report, err := app.Scan(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.CoverageComplete {
		t.Fatal("a truncated traversal must not claim complete coverage")
	}
	if len(report.Coverage.TruncatedRoots) != 1 || report.Coverage.TruncatedRoots[0] != root {
		t.Fatalf("truncated roots = %v, want [%s]", report.Coverage.TruncatedRoots, root)
	}
	if !report.Coverage.Roots[0].Truncated {
		t.Fatal("root coverage must record the truncation")
	}
	if report.Coverage.FilesExamined+report.Coverage.DirectoriesExamined > cfg.MaxFiles {
		t.Fatalf("examined %d files and %d directories with a budget of %d",
			report.Coverage.FilesExamined, report.Coverage.DirectoriesExamined, cfg.MaxFiles)
	}
}

// TestCoverageCompletesOnFullyReadableTree is the positive control: when the
// whole tree is readable and within budget, coverage is complete.
func TestCoverageCompletesOnFullyReadableTree(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "privtool"), 0o755)
	makeDir(t, filepath.Join(root, "srv", "shared"), 0o755)

	report, err := app.Scan(context.Background(), scanConfig(root, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.Status != models.CoverageComplete {
		t.Fatalf("coverage status = %q, want complete: %+v", report.Coverage.Status, report.Coverage)
	}
	if !report.Coverage.ExecutionComplete || !report.Coverage.CoverageComplete {
		t.Fatalf("both completeness flags must be true: %+v", report.Coverage)
	}
	if report.Coverage.FilesExamined == 0 || report.Coverage.DirectoriesExamined == 0 {
		t.Fatalf("coverage must count examined entries: %+v", report.Coverage)
	}
	// A rule whose data category is genuinely empty is recorded as skipped but
	// must not downgrade coverage: there was nothing to assess, not a gap.
	for _, skipped := range report.Coverage.SkippedRules {
		if !strings.Contains(skipped.Reason, "missing observations") {
			t.Fatalf("unexpected skip reason: %+v", skipped)
		}
	}
}
