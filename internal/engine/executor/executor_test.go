package executor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type fakeCollector struct {
	name string
	obs  []models.Observation
	err  error
}

func (f fakeCollector) Name() string { return f.name }

func (f fakeCollector) Collect(context.Context) ([]models.Observation, error) {
	return f.obs, f.err
}

type fakeRule struct {
	meta     models.RuleMetadata
	evaluate func(context.Context, interfaces.ObservationSet) (models.RuleResult, error)
}

func (f fakeRule) Metadata() models.RuleMetadata { return f.meta }

func (f fakeRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	if f.evaluate == nil {
		return models.RuleResult{}, nil
	}
	return f.evaluate(ctx, obs)
}

func testMeta(id string, required ...models.Kind) models.RuleMetadata {
	return models.RuleMetadata{
		ID: id, Version: "1.0.0", Name: "Rule " + id, Description: "desc",
		Category: "test", Module: "test", Severity: models.SeverityLow,
		Confidence: models.ConfidenceHigh, Required: required, Platforms: []string{"linux"},
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func observation(kind models.Kind, resource string) models.Observation {
	return models.NewObservation(kind, resource, "test", time.Now(), map[string]string{
		models.AttrValue: "0",
	})
}

func findingAndEvidence(t *testing.T, meta models.RuleMetadata, resource string, severity models.Severity) (models.Finding, []models.Evidence) {
	t.Helper()
	obs := observation(models.KindSysctl, resource)
	builder := evidence.New()
	evidenceID := builder.Add(obs, models.AttrValue, "observed value")
	finding := models.NewFinding(meta, resource, models.ResourceSysctl, severity, models.ConfidenceHigh, "Test finding", time.Now())
	finding.Explanation = "because the observation says so"
	finding.AddEvidence(evidenceID)
	return finding, builder.Items()
}

func TestSkipsRuleWithoutRequiredObservations(t *testing.T) {
	rule := fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl)}
	engine := New(
		[]interfaces.Rule{rule},
		[]interfaces.Collector{fakeCollector{name: "c", obs: []models.Observation{observation(models.KindSystemInfo, "host")}}},
		Options{Concurrency: 2}, quietLogger(),
	)

	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 1 || result.Rules[0].Status != StatusSkipped {
		t.Fatalf("want skipped rule, got %+v", result.Rules)
	}
	if !strings.Contains(result.Rules[0].Reason, "system.sysctl") {
		t.Fatalf("skip reason must name the missing kind, got %q", result.Rules[0].Reason)
	}
}

func TestIsolatesRuleFailureAndPanic(t *testing.T) {
	healthy, healthyEvidence := findingAndEvidence(t, testMeta("NULQ-T-001", models.KindSysctl), "/healthy", models.SeverityMedium)
	rules := []interfaces.Rule{
		fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl), evaluate: func(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
			return models.RuleResult{Findings: []models.Finding{healthy}, Evidence: healthyEvidence}, nil
		}},
		fakeRule{meta: testMeta("NULQ-T-002", models.KindSysctl), evaluate: func(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
			return models.RuleResult{}, errors.New("boom")
		}},
		fakeRule{meta: testMeta("NULQ-T-003", models.KindSysctl), evaluate: func(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
			panic("unexpected internal failure")
		}},
	}

	engine := New(rules, []interfaces.Collector{fakeCollector{name: "c", obs: []models.Observation{
		observation(models.KindSysctl, "kernel.kptr_restrict"),
	}}}, Options{Concurrency: 3}, quietLogger())

	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("rule failures must not abort the scan: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("healthy rule output must survive, got %d findings", len(result.Findings))
	}
	statuses := map[string]string{}
	for _, outcome := range result.Rules {
		statuses[outcome.ID] = outcome.Status
	}
	if statuses["NULQ-T-001"] != StatusOK || statuses["NULQ-T-002"] != StatusFailed || statuses["NULQ-T-003"] != StatusFailed {
		t.Fatalf("unexpected rule statuses: %+v", statuses)
	}
}

func TestEnforcesRuleTimeout(t *testing.T) {
	rule := fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl), evaluate: func(ctx context.Context, _ interfaces.ObservationSet) (models.RuleResult, error) {
		<-ctx.Done()
		return models.RuleResult{}, ctx.Err()
	}}
	engine := New(
		[]interfaces.Rule{rule},
		[]interfaces.Collector{fakeCollector{name: "c", obs: []models.Observation{observation(models.KindSysctl, "kernel.kptr_restrict")}}},
		Options{Concurrency: 1, RuleTimeout: 30 * time.Millisecond}, quietLogger(),
	)

	start := time.Now()
	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("rule timeout not enforced, took %s", elapsed)
	}
	if result.Rules[0].Status != StatusFailed || !strings.Contains(result.Rules[0].Error, "deadline") {
		t.Fatalf("want timeout failure, got %+v", result.Rules[0])
	}
}

func TestDeduplicatesAndOrdersFindings(t *testing.T) {
	high, highEvidence := findingAndEvidence(t, testMeta("NULQ-T-001", models.KindSysctl), "/high", models.SeverityHigh)
	low, lowEvidence := findingAndEvidence(t, testMeta("NULQ-T-001", models.KindSysctl), "/low", models.SeverityLow)

	rule := fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl), evaluate: func(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
		return models.RuleResult{
			Findings: []models.Finding{low, high, high},
			Evidence: append(highEvidence, lowEvidence...),
		}, nil
	}}
	engine := New(
		[]interfaces.Rule{rule},
		[]interfaces.Collector{fakeCollector{name: "c", obs: []models.Observation{observation(models.KindSysctl, "kernel.kptr_restrict")}}},
		Options{Concurrency: 1}, quietLogger(),
	)

	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("want 2 findings after dedupe, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityHigh {
		t.Fatalf("HIGH must sort first, got %s", result.Findings[0].Severity)
	}
}

func TestKeepsObservationsFromPartialCollector(t *testing.T) {
	collector := fakeCollector{
		name: "partial",
		obs:  []models.Observation{observation(models.KindSysctl, "kernel.kptr_restrict")},
		err:  errors.New("one subtree was unreadable"),
	}
	rule := fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl)}
	engine := New([]interfaces.Rule{rule}, []interfaces.Collector{collector}, Options{Concurrency: 1}, quietLogger())

	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("partial observations must be retained, got %d", len(result.Observations))
	}
	if result.Collectors[0].Status != StatusFailed {
		t.Fatalf("collector failure must be recorded, got %+v", result.Collectors[0])
	}
	if result.Rules[0].Status != StatusOK {
		t.Fatalf("rule should still run on partial observations, got %+v", result.Rules[0])
	}
}

func TestCancelledContextStopsRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine := New(
		[]interfaces.Rule{fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl)}},
		[]interfaces.Collector{fakeCollector{name: "c"}},
		Options{Concurrency: 1}, quietLogger(),
	)
	if _, err := engine.Run(ctx); err == nil {
		t.Fatal("a cancelled scan must return an error")
	}
}

func TestRejectsInvalidRuleOutput(t *testing.T) {
	rule := fakeRule{meta: testMeta("NULQ-T-001", models.KindSysctl), evaluate: func(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
		finding := models.NewFinding(testMeta("NULQ-T-001"), "/x", models.ResourceSysctl, models.SeverityLow, models.ConfidenceHigh, "t", time.Now())
		finding.Explanation = "e"
		finding.AddEvidence("ev-missing")
		return models.RuleResult{Findings: []models.Finding{finding}}, nil
	}}
	engine := New(
		[]interfaces.Rule{rule},
		[]interfaces.Collector{fakeCollector{name: "c", obs: []models.Observation{observation(models.KindSysctl, "x")}}},
		Options{Concurrency: 1}, quietLogger(),
	)
	result, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Rules[0].Status != StatusFailed {
		t.Fatalf("invalid rule output must fail the rule, got %+v", result.Rules[0])
	}
	if len(result.Findings) != 0 {
		t.Fatal("invalid findings must not reach the report")
	}
}
