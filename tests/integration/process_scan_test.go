package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/app"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/lab"
	"github.com/dustin04x/nulq/internal/reporting"
	"github.com/dustin04x/nulq/internal/version"
)

// These scenarios exercise the complete process pipeline — synthetic /proc
// tree, real linux.process collector, rule registry, NULQ-PROC-001 evaluation,
// evidence and JSON serialisation — without Docker, root or any host process
// modification. File ownership comes from the real filesystem, so a
// root-owned executable cannot be fabricated here; the high-severity class is
// covered by the rule's unit tests, while these scenarios prove the wiring.

func writeProcStatus(t *testing.T, procRoot, pid, name string, uid, euid uint32) {
	t.Helper()
	dir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "Name:\t" + name + "\n" +
		"State:\tS (sleeping)\n" +
		"PPid:\t1\n" +
		"Uid:\t" + strconv.FormatUint(uint64(uid), 10) + "\t" + strconv.FormatUint(uint64(euid), 10) + "\t0\t0\n" +
		"Gid:\t" + strconv.FormatUint(uint64(uid), 10) + "\t" + strconv.FormatUint(uint64(uid), 10) + "\t0\t0\n" +
		"Groups:\t" + strconv.FormatUint(uint64(uid), 10) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeProcStat(t *testing.T, procRoot, pid, start string) {
	t.Helper()
	dir := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rest := []string{"S", "1", "1", "1", "0", "-1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "20", "0", "1", "0", start}
	line := pid + " (fixture process) " + strings.Join(rest, " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

// addFixtureProcess writes one synthetic process that executes exe.
func addFixtureProcess(t *testing.T, procRoot, pid, name string, uid, euid uint32, exe string) {
	t.Helper()
	writeProcStatus(t, procRoot, pid, name, uid, euid)
	writeProcStat(t, procRoot, pid, "9000")
	if err := os.Symlink(exe, filepath.Join(procRoot, pid, "exe")); err != nil {
		t.Fatal(err)
	}
}

func processScanConfig(procRoot string) app.ScanConfig {
	return app.ScanConfig{
		Modules:             []string{"process"},
		Concurrency:         2,
		RuleTimeout:         10 * time.Second,
		CollectorTimeout:    30 * time.Second,
		IncludeObservations: true,
		ProcRoot:            procRoot,
		Tool:                version.Info{Version: "test", GoVersion: "go-test", Platform: "linux/amd64"},
	}
}

func scanProcess(t *testing.T, procRoot string) models.Report {
	t.Helper()
	report, err := app.Scan(context.Background(), processScanConfig(procRoot), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return report
}

func collectorNamed(report models.Report, name string) (models.CollectorStatus, bool) {
	for _, collector := range report.Stats.Collectors {
		if collector.Name == name {
			return collector, true
		}
	}
	return models.CollectorStatus{}, false
}

// SCN-PROC-001: the process rule is registered, the collector is activated by
// its required observation kind, and a running process whose executable the
// assessed user can replace produces an evidence-backed finding.
func TestScenarioProcessWritableParentIsDetected(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	writable := filepath.Join(root, "opt", "tools")
	makeDir(t, writable, 0o777)
	exe := filepath.Join(writable, "helper")
	writeFile(t, exe, 0o4755)

	// The executable is owned by the test account, so the set-user-ID bit alone
	// cannot make it root-privileged; the process identity below is another
	// account, which is the boundary the rule must report.
	addFixtureProcess(t, procRoot, "401", "helper", 0, 0, exe)
	addFixtureProcess(t, procRoot, "402", "helper", 0, 0, exe)
	addFixtureProcess(t, procRoot, "403", "helper", 0, 0, exe)

	report := scanProcess(t, procRoot)

	collector, ok := collectorNamed(report, "linux.process")
	if !ok {
		t.Fatalf("linux.process did not run; collectors = %+v", report.Stats.Collectors)
	}
	if collector.Status != "ok" {
		t.Fatalf("collector status = %s (%s)", collector.Status, collector.Error)
	}
	if collector.Observations != 3 {
		t.Fatalf("collector observations = %d, want 3", collector.Observations)
	}

	processObservations := 0
	for _, observation := range report.Observations {
		if observation.Kind == models.KindProcess {
			processObservations++
		}
	}
	if processObservations != 3 {
		t.Fatalf("report carries %d process observations, want 3", processObservations)
	}

	// Three processes share one executable: the relationship is reported once.
	var findings []models.Finding
	for _, finding := range report.Findings {
		if finding.RuleID == "NULQ-PROC-001" {
			findings = append(findings, finding)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("NULQ-PROC-001 findings = %d, want 1 (%+v)", len(findings), report.Findings)
	}
	finding := findings[0]
	if finding.Resource != exe {
		t.Fatalf("resource = %q, want %q", finding.Resource, exe)
	}
	if finding.Severity != models.SeverityInfo || finding.Confidence != models.ConfidenceMedium {
		t.Fatalf("severity/confidence = %s/%s, want INFO/MEDIUM", finding.Severity, finding.Confidence)
	}
	if finding.Title != "Executable consumed by a running process is replaceable by the assessed user" {
		t.Fatalf("title = %q", finding.Title)
	}
	if !strings.Contains(finding.Explanation, "3 observed process(es)") {
		t.Fatalf("finding does not group the processes: %s", finding.Explanation)
	}

	known := map[string]struct{}{}
	for _, evidence := range report.Evidence {
		known[evidence.ID] = struct{}{}
	}
	if len(finding.Evidence) == 0 {
		t.Fatal("finding cites no evidence")
	}
	for _, id := range finding.Evidence {
		if _, ok := known[id]; !ok {
			t.Fatalf("finding cites evidence %s that is absent from the report", id)
		}
	}

	// The report must survive serialisation and schema validation.
	var buffer bytes.Buffer
	if err := reporting.JSON(&buffer, report); err != nil {
		t.Fatalf("serialise: %v", err)
	}
	var document any
	if err := json.Unmarshal(buffer.Bytes(), &document); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	schema, err := lab.LoadSchema(filepath.Join("..", "..", "schemas", "nulq-report-v1.schema.json"))
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	if problems := schema.Validate(document); len(problems) > 0 {
		t.Fatalf("report violates its schema: %v", problems)
	}

	// Determinism: the same tree must produce the same finding identifier.
	again := scanProcess(t, procRoot)
	if len(again.Findings) != 1 || again.Findings[0].ID != finding.ID {
		t.Fatalf("second scan produced %+v, want finding %s", again.Findings, finding.ID)
	}
}

// SCN-PROC-002 (negative control): a directory the assessed user can write to
// is not a permission-boundary weakness when the executable belongs to that
// same user and runs with that user's authority.
func TestScenarioProcessSelfOwnedExecutableIsSilent(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	work := filepath.Join(root, "work")
	makeDir(t, work, 0o777)
	exe := filepath.Join(work, "script-runner")
	writeFile(t, exe, 0o755)
	uid := uint32(os.Geteuid())

	addFixtureProcess(t, procRoot, "500", "script-runner", uid, uid, exe)

	report := scanProcess(t, procRoot)
	if _, ok := collectorNamed(report, "linux.process"); !ok {
		t.Fatal("linux.process did not run")
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "NULQ-PROC-001" {
			t.Fatalf("self-owned unprivileged executable produced %s (%s)", finding.ID, finding.Title)
		}
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %+v, want none for the process module", report.Findings)
	}
}

// SCN-PROC-003: a process whose metadata cannot be read is recorded as
// unavailable and never becomes a finding.
func TestScenarioProcessUnreadableIsNotAFinding(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(procRoot, "600"), 0o755); err != nil {
		t.Fatal(err)
	}
	// No status file: the collector must publish an unavailable observation.
	writeProcStat(t, procRoot, "600", "7000")

	report := scanProcess(t, procRoot)
	unavailable := 0
	for _, observation := range report.Observations {
		if observation.Kind == models.KindProcess && observation.Status != models.StatusComplete {
			unavailable++
		}
	}
	if unavailable != 1 {
		t.Fatalf("unavailable process observations = %d, want 1", unavailable)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("unreadable process produced findings: %+v", report.Findings)
	}
	// The gap is recorded as an unavailable observation rather than silently
	// dropped, and it is still counted in the report statistics (the count is
	// report-wide, so host observations such as an absent sysctl may add to it).
	if report.Stats.UnavailableObservations < unavailable {
		t.Fatalf("stats.unavailable_observations = %d, want at least %d",
			report.Stats.UnavailableObservations, unavailable)
	}
}

// The process collector is bound to rule selection, not to the scan command:
// a filesystem-only scan must not enumerate /proc.
func TestScenarioProcessCollectorIsGatedByRuleSelection(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "bin", "tool"), 0o755)
	cfg := app.ScanConfig{
		Modules:          []string{"filesystem"},
		Concurrency:      2,
		RuleTimeout:      10 * time.Second,
		CollectorTimeout: 30 * time.Second,
		ScanRoots:        []string{root},
		MaxFiles:         500,
		Tool:             version.Info{Version: "test", GoVersion: "go-test", Platform: "linux/amd64"},
	}
	report, err := app.Scan(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, ok := collectorNamed(report, "linux.process"); ok {
		t.Fatal("linux.process ran for a filesystem-only scan")
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "NULQ-PROC-001" {
			t.Fatalf("process rule produced %s without process observations", finding.ID)
		}
	}
}
