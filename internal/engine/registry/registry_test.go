package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
)

type stubRule struct {
	meta models.RuleMetadata
}

func (s stubRule) Metadata() models.RuleMetadata { return s.meta }

func (s stubRule) Evaluate(context.Context, interfaces.ObservationSet) (models.RuleResult, error) {
	return models.RuleResult{}, nil
}

func ruleSet(rules ...stubRule) []interfaces.Rule {
	out := make([]interfaces.Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule)
	}
	return out
}

func metadata(id, module string) models.RuleMetadata {
	return models.RuleMetadata{
		ID: id, Version: "1.0.0", Name: "Rule " + id, Description: "desc",
		Category: "test", Module: module, Severity: models.SeverityLow,
		Confidence: models.ConfidenceHigh, Required: []models.Kind{models.KindFile},
		Platforms: []string{"linux"},
	}
}

func TestRegistryRejectsInvalidAndDuplicateRules(t *testing.T) {
	if _, err := New(ruleSet(stubRule{meta: metadata("", "test")})); err == nil {
		t.Fatal("expected invalid metadata to be rejected")
	}
	if _, err := New(ruleSet(
		stubRule{meta: metadata("NULQ-T-001", "test")},
		stubRule{meta: metadata("NULQ-T-001", "test")},
	)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rule rejection, got %v", err)
	}
}

func TestRegistrySelectsByModuleAndID(t *testing.T) {
	registry, err := New(ruleSet(
		stubRule{meta: metadata("NULQ-T-001", "alpha")},
		stubRule{meta: metadata("NULQ-T-002", "alpha")},
		stubRule{meta: metadata("NULQ-T-003", "beta")},
	))
	if err != nil {
		t.Fatal(err)
	}

	all, err := registry.Select(nil, nil)
	if err != nil || len(all) != 3 {
		t.Fatalf("select all: %v, %d rules", err, len(all))
	}
	alpha, err := registry.Select([]string{"alpha"}, nil)
	if err != nil || len(alpha) != 2 {
		t.Fatalf("select alpha: %v, %d rules", err, len(alpha))
	}
	intersection, err := registry.Select([]string{"alpha"}, []string{"NULQ-T-002"})
	if err != nil || len(intersection) != 1 || intersection[0].Metadata().ID != "NULQ-T-002" {
		t.Fatalf("intersection selection: %v, %+v", err, intersection)
	}
	if modules := registry.Modules(); len(modules) != 2 || modules[0] != "alpha" || modules[1] != "beta" {
		t.Fatalf("modules = %v", modules)
	}
}

func TestRegistryRejectsUnknownSelection(t *testing.T) {
	registry, err := New(ruleSet(stubRule{meta: metadata("NULQ-T-001", "alpha")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Select([]string{"missing"}, nil); err == nil {
		t.Fatal("unknown module must be rejected")
	}
	if _, err := registry.Select(nil, []string{"NULQ-T-999"}); err == nil {
		t.Fatal("unknown rule ID must be rejected")
	}
}
