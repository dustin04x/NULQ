package lab

import (
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

func labFinding(ruleID, resource string, severity models.Severity) models.Finding {
	meta := models.RuleMetadata{
		ID: ruleID, Version: "1.0.0", Name: "n", Description: "d", Category: "c",
		Module: "filesystem", Severity: models.SeverityLow, Confidence: models.ConfidenceHigh,
		Required: []models.Kind{models.KindFile}, Platforms: []string{"linux"},
	}
	finding := models.NewFinding(meta, resource, models.ResourceFile, severity, models.ConfidenceHigh, "title", time.Unix(0, 0))
	finding.Explanation = "explanation"
	finding.AddEvidence("ev-0123456789ab")
	return finding
}

func artifactWith(findings ...models.Finding) ScanArtifact {
	report := validReport()
	report.Findings = findings
	for _, finding := range findings {
		for _, id := range finding.Evidence {
			report.Evidence = append(report.Evidence, models.Evidence{
				ID: id, ObservationID: "obs-file-0123456789ab", Resource: finding.Resource,
				ResourceKind: models.ResourceFile, Collector: "test", Field: "mode",
				ObservedValue: "4755", Explanation: "test evidence", CollectedAt: time.Unix(0, 0).UTC(),
			})
		}
	}
	report.Normalize()
	return ScanArtifact{Name: "fixtures", Artifact: "scan-fixtures.json", Loaded: true, Report: report}
}

func manifestWith(scenarios ...Scenario) Manifest {
	return Manifest{
		SchemaVersion: "1.0",
		Target:        "test",
		Artifacts:     map[string]string{"fixtures": "scan-fixtures.json"},
		Scenarios:     scenarios,
	}
}

func fullIsolation() Isolation {
	return Isolation{
		UID: 10001, NonRoot: true, ReadOnlyRoot: true,
		EffectiveCapabilities: "0000000000000000", CapabilitiesDropped: true,
		NoNewPrivileges: true, NetworkInterfaces: "lo", NetworkIsolated: true,
		NulqExecutable: true, TmpWritable: true, TmpNoExec: true,
	}
}

func TestEvaluatePassesMatchingScenario(t *testing.T) {
	scenario := Scenario{
		ID: "FS-001", Title: "finding", Category: "filesystem", Environment: "synthetic",
		Supported: true, Scan: "fixtures", Scope: []string{"/lab/"},
		Expect: Expectations{Findings: []FindingExpectation{{
			RuleID: "NULQ-FS-001", Resource: "/lab/tool", Match: "exact",
			Severity: "MEDIUM", Confidence: "HIGH",
		}}},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/tool", models.SeverityMedium))},
		fullIsolation(), ImageInfo{})

	if !result.Summary.Passed {
		t.Fatalf("expected pass, got %+v", result.Summary)
	}
	if result.Summary.ScenariosPassed != 1 || result.Summary.MissingFindings != 0 {
		t.Fatalf("unexpected summary: %+v", result.Summary)
	}
	if len(result.Scenarios[0].Checks) == 0 {
		t.Fatal("a pass must still record its checks")
	}
}

func TestEvaluateMissingFindingFails(t *testing.T) {
	scenario := Scenario{
		ID: "FS-002", Title: "finding", Category: "filesystem", Environment: "synthetic",
		Supported: true, Scan: "fixtures",
		Expect: Expectations{Findings: []FindingExpectation{{
			RuleID: "NULQ-FS-001", Resource: "/lab/missing", Match: "exact",
		}}},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith()}, fullIsolation(), ImageInfo{})

	if result.Summary.Passed {
		t.Fatal("missing finding must fail the run")
	}
	if result.Summary.MissingFindings != 1 {
		t.Fatalf("missing findings = %d, want 1", result.Summary.MissingFindings)
	}
	if result.Scenarios[0].Status != "failed" {
		t.Fatalf("scenario status = %q", result.Scenarios[0].Status)
	}
}

func TestEvaluateSeverityMismatchFails(t *testing.T) {
	scenario := Scenario{
		ID: "FS-003", Title: "severity", Category: "filesystem", Environment: "synthetic",
		Supported: true, Scan: "fixtures",
		Expect: Expectations{Findings: []FindingExpectation{{
			RuleID: "NULQ-FS-001", Resource: "/lab/tool", Match: "exact", Severity: "LOW",
		}}},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/tool", models.SeverityHigh))},
		fullIsolation(), ImageInfo{})

	if result.Summary.Passed {
		t.Fatal("severity mismatch must fail")
	}
	if result.Summary.SeverityMismatches != 1 {
		t.Fatalf("severity mismatches = %d, want 1", result.Summary.SeverityMismatches)
	}
}

func TestEvaluateUnexpectedFindingInScopeFails(t *testing.T) {
	scenario := Scenario{
		ID: "FS-004", Title: "scope", Category: "filesystem", Environment: "synthetic",
		Supported: true, Scan: "fixtures", Scope: []string{"/lab/"},
		Expect: Expectations{AbsentFindings: []FindingExpectation{{
			RuleID: "NULQ-FS-009", Match: "any",
		}}},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/extra", models.SeverityMedium))},
		fullIsolation(), ImageInfo{})

	if result.Summary.UnexpectedFindings != 1 {
		t.Fatalf("unexpected = %d, want 1", result.Summary.UnexpectedFindings)
	}
	if result.Summary.Passed {
		t.Fatal("unexpected finding must fail the scenario")
	}
}

func TestAbsentFindingHonoursSeverityFilter(t *testing.T) {
	scenario := Scenario{
		ID: "FS-005", Title: "absent severity", Category: "filesystem",
		Environment: "synthetic", Supported: true, Scan: "fixtures",
		Expect: Expectations{
			AbsentFindings: []FindingExpectation{{
				RuleID: "NULQ-FS-001", Resource: "/lab/tool", Match: "exact", Severity: "HIGH",
			}},
			AllowedFindings: []FindingExpectation{{
				RuleID: "NULQ-FS-001", Resource: "/lab/tool", Match: "exact",
			}},
		},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/tool", models.SeverityMedium))},
		fullIsolation(), ImageInfo{})

	if !result.Summary.Passed {
		t.Fatalf("a MEDIUM finding must not violate an absent-HIGH assertion: %+v", result.Scenarios[0].Checks)
	}
}

func TestUnaccountedFindingFailsWithoutScope(t *testing.T) {
	scenario := Scenario{
		ID: "FS-021", Title: "unaccounted", Category: "filesystem",
		Environment: "synthetic", Supported: true, Scan: "fixtures",
		Expect: Expectations{MaxSeverity: "HIGH"},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/extra", models.SeverityMedium))},
		fullIsolation(), ImageInfo{})
	if result.Summary.UnaccountedFindings != 1 {
		t.Fatalf("unaccounted findings = %d, want 1", result.Summary.UnaccountedFindings)
	}
	if result.Summary.Passed {
		t.Fatal("an unasserted, unallowed finding must fail the run even without scope")
	}
	if len(result.Findings.Unaccounted) != 1 || result.Findings.Unaccounted[0].Scenario != "unaccounted:fixtures" {
		t.Fatalf("unaccounted = %+v", result.Findings.Unaccounted)
	}
}

func TestAllowedFindingIsAccounted(t *testing.T) {
	scenario := Scenario{
		ID: "FS-022", Title: "allowed", Category: "filesystem",
		Environment: "synthetic", Supported: true, Scan: "fixtures",
		Expect: Expectations{
			MaxSeverity: "HIGH",
			AllowedFindings: []FindingExpectation{{
				RuleID: "NULQ-FS-001", Resource: "/lab/extra", Match: "exact",
			}},
		},
	}
	result := Evaluate(manifestWith(scenario),
		map[string]ScanArtifact{"fixtures": artifactWith(labFinding("NULQ-FS-001", "/lab/extra", models.SeverityMedium))},
		fullIsolation(), ImageInfo{})
	if result.Summary.UnaccountedFindings != 0 {
		t.Fatalf("allowed finding counted as unaccounted: %+v", result.Findings.Unaccounted)
	}
	if !result.Summary.Passed {
		t.Fatalf("an explicitly allowed finding must not fail the run: %+v", result.Summary)
	}
}

func TestIntegrityDetectsDuplicateFindings(t *testing.T) {
	one := labFinding("NULQ-FS-001", "/lab/tool", models.SeverityLow)
	two := one
	two.ID = "fnd-ffffffffffff"
	result := Evaluate(manifestWith(),
		map[string]ScanArtifact{"fixtures": artifactWith(one, two)}, fullIsolation(), ImageInfo{})
	if result.Summary.DuplicateFindings != 1 {
		t.Fatalf("duplicate findings = %d, want 1", result.Summary.DuplicateFindings)
	}
	if result.Summary.Passed {
		t.Fatal("duplicate findings must fail the run")
	}
	if len(result.Findings.Duplicates) != 1 || result.Findings.Duplicates[0].RuleID != "NULQ-FS-001" {
		t.Fatalf("duplicate evidence = %+v", result.Findings.Duplicates)
	}
}

func TestIntegrityDetectsDanglingEvidence(t *testing.T) {
	finding := labFinding("NULQ-FS-001", "/lab/tool", models.SeverityLow)
	artifact := artifactWith(finding)
	artifact.Report.Evidence = nil
	result := Evaluate(manifestWith(),
		map[string]ScanArtifact{"fixtures": artifact}, fullIsolation(), ImageInfo{})
	if result.Summary.DanglingEvidence != 1 {
		t.Fatalf("dangling evidence = %d, want 1", result.Summary.DanglingEvidence)
	}
	if result.Summary.Passed {
		t.Fatal("dangling evidence must fail the run")
	}
}

func TestIntegrityDetectsMissingEvidence(t *testing.T) {
	finding := labFinding("NULQ-FS-001", "/lab/tool", models.SeverityLow)
	finding.Evidence = nil
	result := Evaluate(manifestWith(),
		map[string]ScanArtifact{"fixtures": artifactWith(finding)}, fullIsolation(), ImageInfo{})
	if result.Summary.FindingsWithoutEvidence != 1 {
		t.Fatalf("findings without evidence = %d, want 1", result.Summary.FindingsWithoutEvidence)
	}
	if result.Summary.Passed {
		t.Fatal("a finding without evidence must fail the run")
	}
}

func TestUnsupportedScenarioIsNeverAPass(t *testing.T) {
	scenario := Scenario{
		ID: "CAP-001", Title: "capabilities", Category: "capabilities",
		Environment: "unsupported", Supported: false, Reason: "M3",
	}
	result := Evaluate(manifestWith(scenario), map[string]ScanArtifact{}, fullIsolation(), ImageInfo{})

	if result.Summary.ScenariosPassed != 0 {
		t.Fatalf("unsupported scenario counted as passed: %+v", result.Summary)
	}
	if result.Summary.ScenariosUnsupported != 1 || result.Scenarios[0].Status != "unsupported" {
		t.Fatalf("unexpected verdict: %+v", result.Scenarios[0])
	}
}

func TestIsolationFailureFailsRun(t *testing.T) {
	isolation := fullIsolation()
	isolation.ReadOnlyRoot = false
	result := Evaluate(manifestWith(), map[string]ScanArtifact{}, isolation, ImageInfo{})
	if result.Isolation.Passed {
		t.Fatal("a writable root filesystem must fail isolation verification")
	}
	if result.Summary.Passed {
		t.Fatal("run must fail when isolation is not established")
	}
}

func TestSchemaInvalidScanFailsScenario(t *testing.T) {
	scenario := Scenario{
		ID: "FS-006", Title: "schema", Category: "filesystem", Environment: "synthetic",
		Supported: true, Scan: "fixtures",
		Expect: Expectations{MaxSeverity: "LOW"},
	}
	artifact := artifactWith()
	artifact.SchemaErrors = []string{"$.findings: bad"}
	result := Evaluate(manifestWith(scenario), map[string]ScanArtifact{"fixtures": artifact}, fullIsolation(), ImageInfo{})

	if result.Summary.Passed {
		t.Fatal("a schema-invalid scan must fail")
	}
	if result.Summary.ScansInvalid != 1 {
		t.Fatalf("invalid scans = %d, want 1", result.Summary.ScansInvalid)
	}
}
