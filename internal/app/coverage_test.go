package app

import (
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/executor"
)

func mountObservation(point string, assessed bool, reason string) models.Observation {
	obs := models.NewObservation(models.KindMount, point, "test", time.Now().UTC(), nil)
	obs.Set(models.AttrAssessed, boolString(assessed))
	if reason != "" {
		obs.Set(models.AttrExclusionReason, reason)
	}
	return obs
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestCoverageReportsExcludedRootsSeparately(t *testing.T) {
	result := executor.Result{
		Observations: []models.Observation{
			mountObservation("/", true, ""),
			mountObservation("/proc", false, "pseudo_filesystem"),
			mountObservation("/var/lib/docker", false, "excluded_path"),
			mountObservation("/home", false, ""), // explicit scope, not a policy exclusion
		},
		Collectors: []executor.CollectorOutcome{{Name: "linux.filesystem", Status: executor.StatusOK}},
		Rules:      []executor.RuleOutcome{{ID: "NULQ-FS-001", Status: executor.StatusOK}},
	}
	coverage := buildCoverage(result)
	if len(coverage.ExcludedRoots) != 2 {
		t.Fatalf("excluded roots = %v, want /proc and /var/lib/docker", coverage.ExcludedRoots)
	}
	if coverage.ExcludedRoots[0] != "/proc" || coverage.ExcludedRoots[1] != "/var/lib/docker" {
		t.Fatalf("excluded roots must be sorted and exclude non-policy scope: %v", coverage.ExcludedRoots)
	}
	if coverage.Status != models.CoverageComplete {
		t.Fatalf("a deliberate exclusion is not a traversal failure: %+v", coverage)
	}
}

func TestCoverageClassifiesFailedOperations(t *testing.T) {
	result := executor.Result{
		Collectors: []executor.CollectorOutcome{{
			Name: "linux.filesystem", Status: executor.StatusFailed,
			Class: "timeout", Error: "collect: timeout: deadline exceeded",
		}},
		Rules: []executor.RuleOutcome{
			{ID: "NULQ-FS-003", Status: executor.StatusSkipped, Class: "canceled", Reason: "scan canceled"},
			{ID: "NULQ-SYS-002", Status: executor.StatusSkipped, Reason: "missing observations: security_control"},
		},
	}
	coverage := buildCoverage(result)
	if coverage.ExecutionComplete {
		t.Fatal("timed-out collector and cancelled rule must make execution incomplete")
	}
	if coverage.Status != models.CoverageFailed {
		t.Fatalf("status = %q, want failed", coverage.Status)
	}
	if len(coverage.FailedOperations) != 2 {
		t.Fatalf("failed operations = %+v, want collector timeout and rule cancellation", coverage.FailedOperations)
	}
	if coverage.FailedOperations[0].Operation != "collector:linux.filesystem" || coverage.FailedOperations[0].Class != "timeout" {
		t.Fatalf("collector failure = %+v", coverage.FailedOperations[0])
	}
	if len(coverage.SkippedRules) != 1 || coverage.SkippedRules[0].RuleID != "NULQ-SYS-002" {
		t.Fatalf("a rule skipped for missing observations is not a failed operation: %+v", coverage.SkippedRules)
	}
}

func TestCoverageUnclassifiedErrorIsExplicit(t *testing.T) {
	result := executor.Result{
		Rules: []executor.RuleOutcome{{
			ID: "NULQ-FS-001", Status: executor.StatusFailed, Error: "invalid rule output",
		}},
	}
	coverage := buildCoverage(result)
	if len(coverage.FailedOperations) != 1 {
		t.Fatalf("failed operations = %+v", coverage.FailedOperations)
	}
	if coverage.FailedOperations[0].Class != "unclassified" {
		t.Fatalf("class = %q, want unclassified", coverage.FailedOperations[0].Class)
	}
}
