package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestSafeID_PathTraversalRejection(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"empty", "", true},
		{"relative up", "..", true},
		{"relative up nested", "foo/../bar", true},
		{"absolute path", "/etc/passwd", true},
		{"absolute path windows", `C:\Windows`, true},
		{"contains slash", "foo/bar", true},
		{"contains backslash", `foo\bar`, true},
		{"valid alphanumeric", "report-123", false},
		{"valid with dash", "my-report", false},
		{"valid with underscore", "my_report", false},
		{"valid mixed", "report_abc-123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := safeID(tt.id)
			if tt.wantErr && err == nil {
				t.Errorf("safeID(%q) expected error, got nil", tt.id)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("safeID(%q) unexpected error: %v", tt.id, err)
			}
		})
	}
}

func TestStore_SaveReport_PathTraversalRejection(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	invalidIDs := []string{"../escape", "/absolute", "foo/../bar", `C:\Windows`}
	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			r := minimalReport(id)
			err := s.SaveReport(r)
			if err == nil {
				t.Errorf("SaveReport with id %q expected error, got nil", id)
			}
		})
	}
}

func TestStore_SaveReport_SymlinkRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	// Create a real report first
	r := minimalReport("report-1")
	if err := s.SaveReport(r); err != nil {
		t.Fatalf("SaveReport failed: %v", err)
	}

	// Replace the report file with a symlink
	reportPath := filepath.Join(tmpDir, "reports", "report-1.json")
	target := filepath.Join(tmpDir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(reportPath); err != nil {
		t.Fatalf("remove report: %v", err)
	}
	if err := os.Symlink(target, reportPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// LoadReport should refuse the symlink
	_, err := s.LoadReport("report-1")
	if err == nil {
		t.Error("LoadReport expected error for symlink, got nil")
	}
	if err != nil && err.Error() != "refusing symlink" {
		t.Errorf("LoadReport unexpected error: %v", err)
	}

	// DeleteReport should also refuse the symlink
	err = s.DeleteReport("report-1")
	if err == nil {
		t.Error("DeleteReport expected error for symlink, got nil")
	}
	if err != nil && err.Error() != "refusing symlink" {
		t.Errorf("DeleteReport unexpected error: %v", err)
	}
}

func TestStore_SaveReport_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	r := minimalReport("report-atomic")
	if err := s.SaveReport(r); err != nil {
		t.Fatalf("SaveReport failed: %v", err)
	}

	reportPath := filepath.Join(tmpDir, "reports", "report-atomic.json")
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}

	// File should exist and not be a temp file
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("report file should not be a symlink")
	}

	// No .tmp file should remain
	tmpPath := reportPath + ".tmp"
	if _, err := os.Stat(tmpPath); err == nil {
		t.Error("temp file should have been renamed")
	} else if !os.IsNotExist(err) {
		t.Errorf("stat temp file: %v", err)
	}

	// Content should be valid JSON
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var parsed models.Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("report is not valid JSON: %v", err)
	}
	if parsed.Scan.ReportID != "report-atomic" {
		t.Errorf("report ID mismatch: got %q", parsed.Scan.ReportID)
	}
}

func TestStore_LoadReport_CorruptJSON(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	// Write corrupt JSON directly
	reportPath := filepath.Join(tmpDir, "reports", "corrupt.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(reportPath, []byte("{ not valid json"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	_, err := s.LoadReport("corrupt")
	if err == nil {
		t.Error("LoadReport expected error for corrupt JSON, got nil")
	}
}

func TestStore_LoadReport_WrongSchemaVersion(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	// Write report with wrong schema version
	reportPath := filepath.Join(tmpDir, "reports", "wrongver.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := minimalReport("wrongver")
	r.SchemaVersion = "0.0"
	data, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(reportPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := s.LoadReport("wrongver")
	if err == nil {
		t.Error("LoadReport expected error for wrong schema version, got nil")
	}
}

func TestStore_SaveReport_DuplicateIDRejection(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	r := minimalReport("dup-report")
	if err := s.SaveReport(r); err != nil {
		t.Fatalf("first SaveReport failed: %v", err)
	}

	// Second save with same ID should fail
	err := s.SaveReport(r)
	if err == nil {
		t.Error("SaveReport with duplicate ID expected error, got nil")
	}
	if err != nil && !contains(err.Error(), "already exists") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestStore_LoadReport_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	_, err := s.LoadReport("nonexistent")
	if err == nil {
		t.Error("LoadReport expected error for nonexistent report, got nil")
	}
	if err != nil && !os.IsNotExist(err) {
		t.Errorf("expected NotExist error, got: %v", err)
	}
}

func TestStore_DeleteReport_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	err := s.DeleteReport("nonexistent")
	if err == nil {
		t.Error("DeleteReport expected error for nonexistent report, got nil")
	}
	if err != nil && !os.IsNotExist(err) {
		t.Errorf("expected NotExist error, got: %v", err)
	}
}

func TestStore_ListReports(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	ids := []string{"report-a", "report-b", "report-c"}
	for _, id := range ids {
		if err := s.SaveReport(minimalReport(id)); err != nil {
			t.Fatalf("SaveReport(%s): %v", id, err)
		}
	}

	listed, err := s.ListReports()
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}

	if len(listed) != len(ids) {
		t.Errorf("ListReports returned %d ids, want %d", len(listed), len(ids))
	}
	for i, id := range listed {
		if id != ids[i] {
			t.Errorf("ListReports[%d] = %q, want %q", i, id, ids[i])
		}
	}
}

func TestStore_Baseline_SymlinkRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	// Create a report first
	r := minimalReport("report-for-baseline")
	if err := s.SaveReport(r); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	// Create baseline
	if err := s.CreateBaseline("baseline-1", "report-for-baseline", "desc"); err != nil {
		t.Fatalf("CreateBaseline: %v", err)
	}

	// Replace baseline file with symlink
	baselinePath := filepath.Join(tmpDir, "baselines", "baseline-1.json")
	target := filepath.Join(tmpDir, "target-baseline.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(baselinePath); err != nil {
		t.Fatalf("remove baseline: %v", err)
	}
	if err := os.Symlink(target, baselinePath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// LoadBaseline should refuse
	_, err := s.LoadBaseline("baseline-1")
	if err == nil {
		t.Error("LoadBaseline expected error for symlink, got nil")
	}
	if err != nil && !contains(err.Error(), "refusing symlink") {
		t.Errorf("unexpected error: %v", err)
	}

	// DeleteBaseline should refuse
	err = s.DeleteBaseline("baseline-1")
	if err == nil {
		t.Error("DeleteBaseline expected error for symlink, got nil")
	}
	if err != nil && !contains(err.Error(), "refusing symlink") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_Baseline_DuplicateRejection(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	r := minimalReport("report-for-baseline")
	if err := s.SaveReport(r); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	if err := s.CreateBaseline("dup-base", "report-for-baseline", "desc"); err != nil {
		t.Fatalf("first CreateBaseline: %v", err)
	}

	err := s.CreateBaseline("dup-base", "report-for-baseline", "desc")
	if err == nil {
		t.Error("CreateBaseline with duplicate name expected error, got nil")
	}
	if err != nil && !contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_Baseline_ReportNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	err := s.CreateBaseline("base", "nonexistent-report", "desc")
	if err == nil {
		t.Error("CreateBaseline expected error for missing report, got nil")
	}
	if err != nil && !contains(err.Error(), "report not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCompareReports(t *testing.T) {
	base := minimalReport("baseline-report")
	base.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: []string{"e1"}},
		{ID: "f2", RuleID: "R002", Resource: "/etc/shadow", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Evidence: []string{"e2"}},
	}
	base.Normalize()

	current := minimalReport("current-report")
	current.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: []string{"e1"}},
		{ID: "f3", RuleID: "R003", Resource: "/etc/group", Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Evidence: []string{"e3"}},
	}
	current.Normalize()

	diff := CompareReports(base, current)

	if diff.BaselineReportID != "baseline-report" {
		t.Errorf("BaselineReportID = %q, want %q", diff.BaselineReportID, "baseline-report")
	}
	if diff.CurrentReportID != "current-report" {
		t.Errorf("CurrentReportID = %q, want %q", diff.CurrentReportID, "current-report")
	}

	// f2 should be resolved
	if len(diff.Resolved) != 1 || diff.Resolved[0].ID != "f2" {
		t.Errorf("Resolved = %+v, want 1 finding f2", diff.Resolved)
	}

	// f3 should be new
	if len(diff.New) != 1 || diff.New[0].ID != "f3" {
		t.Errorf("New = %+v, want 1 finding f3", diff.New)
	}

	// f1 should be unchanged
	if len(diff.Unchanged) != 1 || diff.Unchanged[0].ID != "f1" {
		t.Errorf("Unchanged = %+v, want 1 finding f1", diff.Unchanged)
	}
}

func TestCompareReports_SeverityChange(t *testing.T) {
	base := minimalReport("base")
	base.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Evidence: []string{"e1"}},
	}
	base.Normalize()

	current := minimalReport("current")
	current.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: []string{"e1"}},
	}
	current.Normalize()

	diff := CompareReports(base, current)

	if len(diff.Changed) != 1 || diff.Changed[0].ID != "f1" {
		t.Errorf("Changed = %+v, want 1 finding f1 with severity change", diff.Changed)
	}
	if diff.Changed[0].SeverityOld != string(models.SeverityLow) {
		t.Errorf("SeverityOld = %q, want %q", diff.Changed[0].SeverityOld, models.SeverityLow)
	}
	if diff.Changed[0].SeverityNew != string(models.SeverityHigh) {
		t.Errorf("SeverityNew = %q, want %q", diff.Changed[0].SeverityNew, models.SeverityHigh)
	}
}

func TestCompareReports_EvidenceChange(t *testing.T) {
	base := minimalReport("base")
	base.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Evidence: []string{"e1"}},
	}
	base.Normalize()

	current := minimalReport("current")
	current.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Evidence: []string{"e1", "e2"}},
	}
	current.Normalize()

	diff := CompareReports(base, current)

	if len(diff.Changed) != 1 || !diff.Changed[0].EvidenceChanged {
		t.Errorf("Changed = %+v, want 1 finding f1 with evidence change", diff.Changed)
	}
}

func TestCompareReports_CoverageIncompleteWarning(t *testing.T) {
	base := minimalReport("base")
	base.Findings = []models.Finding{
		{ID: "f1", RuleID: "R001", Resource: "/etc/passwd", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Evidence: []string{"e1"}},
	}
	base.Coverage.Status = models.CoverageComplete
	base.Normalize()

	current := minimalReport("current")
	current.Coverage.Status = models.CoveragePartial
	current.Normalize()

	diff := CompareReports(base, current)

	found := false
	for _, w := range diff.Warnings {
		if contains(w, "coverage-complete") || contains(w, "inconclusive") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about incomplete coverage, got: %v", diff.Warnings)
	}
}

func minimalReport(id string) models.Report {
	now := time.Now().UTC()
	r := models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool: models.ToolInfo{
			Name:      "nulq",
			Version:   "test",
			GoVersion: "go1.23",
			Platform:  "linux/amd64",
		},
		Host: models.HostInfo{
			Hostname:     "testhost",
			Architecture: "amd64",
		},
		Scan: models.ScanInfo{
			ReportID:   id,
			StartedAt:  now,
			FinishedAt: now.Add(time.Second),
			DurationMS: 1000,
			Modules:    []string{"identity", "filesystem"},
		},
		Findings: []models.Finding{},
		Evidence: []models.Evidence{},
		Stats: models.Stats{
			Observations: 0,
			Findings:     0,
			Evidence:     0,
		},
		Coverage: models.Coverage{
			Status:            models.CoverageComplete,
			ExecutionComplete: true,
			CoverageComplete:  true,
		},
		Limitations: []string{},
	}
	r.Normalize()
	return r
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSafeID_LengthLimit(t *testing.T) {
	if err := safeID(strings.Repeat("a", maxIDLen)); err != nil {
		t.Errorf("safeID expected no error for max-length id, got %v", err)
	}
	if err := safeID(strings.Repeat("a", maxIDLen+1)); err == nil {
		t.Error("safeID expected error for over-long id, got nil")
	}
}

func TestStore_LoadReport_ReportIDMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	reportPath := filepath.Join(tmpDir, "reports", "mismatch.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := minimalReport("mismatch")
	r.Scan.ReportID = "different-id"
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(reportPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = s.LoadReport("mismatch")
	if err == nil {
		t.Error("LoadReport expected error for report id mismatch, got nil")
	}
	if err != nil && !contains(err.Error(), "mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_LoadReport_DeeplyNestedJSONRejected(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	reportPath := filepath.Join(tmpDir, "reports", "deep.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	nested := strings.Repeat("[", 2000) + strings.Repeat("]", 2000)
	if err := os.WriteFile(reportPath, []byte(nested), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := s.LoadReport("deep")
	if err == nil {
		t.Error("LoadReport expected error for deeply nested JSON, got nil")
	}
}

func TestStore_LoadReport_TrailingDataRejected(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	reportPath := filepath.Join(tmpDir, "reports", "trailing.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := minimalReport("trailing")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data = append(data, []byte("{}")...)
	if err := os.WriteFile(reportPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = s.LoadReport("trailing")
	if err == nil {
		t.Error("LoadReport expected error for trailing data, got nil")
	}
}

func TestStore_LoadReport_SizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	reportPath := filepath.Join(tmpDir, "reports", "oversize.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(reportPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(maxReportSize + 1); err != nil {
		f.Close()
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	_, err = s.LoadReport("oversize")
	if err == nil {
		t.Error("LoadReport expected error for oversize report, got nil")
	}
	if err != nil && err.Error() != "report too large" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_SaveReport_SymlinkAtPathRefused(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	reportPath := filepath.Join(tmpDir, "reports", "symlink-at-save.json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(tmpDir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, reportPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	r := minimalReport("symlink-at-save")
	err := s.SaveReport(r)
	if err == nil {
		t.Error("SaveReport expected error when saving over a symlink, got nil")
	}
	if err != nil && err.Error() != "refusing symlink" {
		t.Errorf("unexpected error: %v", err)
	}

	// The symlink target must not have been written through.
	if _, err := os.ReadFile(target); err != nil {
		t.Errorf("target unreadable: %v", err)
	}
	// The symlink must not have been replaced by the report file.
	info, err := os.Lstat(reportPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink should not have been replaced by SaveReport")
	}
}

func TestStore_Baseline_CorruptJSON(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	baselinePath := filepath.Join(tmpDir, "baselines", "corrupt.json")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("{ not valid json"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	_, err := s.LoadBaseline("corrupt")
	if err == nil {
		t.Error("LoadBaseline expected error for corrupt JSON, got nil")
	}
}

func TestStore_ConcurrentSavesSameID(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	r := minimalReport("concurrent")
	const workers = 12
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.SaveReport(r)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly one successful save under concurrency, got %d", successes)
	}

	listed, err := s.ListReports()
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("expected exactly 1 report, got %d", len(listed))
	}
}

func TestStore_ConcurrentLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	s := New(tmpDir)

	if err := s.SaveReport(minimalReport("live")); err != nil {
		t.Fatalf("initial SaveReport: %v", err)
	}

	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if err := s.SaveReport(minimalReport(fmt.Sprintf("worker-%d", i))); err != nil {
				t.Errorf("concurrent SaveReport: %v", err)
			}
		}(i)
		go func() {
			defer wg.Done()
			if _, err := s.LoadReport("live"); err != nil {
				t.Errorf("concurrent LoadReport: %v", err)
			}
		}()
	}
	wg.Wait()

	if _, err := s.ListReports(); err != nil {
		t.Fatalf("ListReports after concurrency: %v", err)
	}
}
