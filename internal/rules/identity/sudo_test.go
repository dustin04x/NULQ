package identity

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func sudoRuleObservation(path string, commands string) models.Observation {
	obs := models.NewObservation(models.KindSudoRule, path, "test", time.Now(), nil)
	if commands != "" {
		obs.Set(models.AttrSudoCommands, commands)
	}
	return obs
}

func TestSudoRulePasswordlessRoot(t *testing.T) {
	file := sudoRuleObservation("/etc/sudoers.d/app", "tester ALL=(root) NOPASSWD: /usr/bin/app")
	result, err := NewSudoRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityMedium {
		t.Fatalf("severity = %s, want MEDIUM", result.Findings[0].Severity)
	}
}

func TestSudoRuleRootWithPassword(t *testing.T) {
	file := sudoRuleObservation("/etc/sudoers.d/app", "tester ALL=(root) /usr/bin/app")
	result, err := NewSudoRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityLow {
		t.Fatalf("severity = %s, want LOW", result.Findings[0].Severity)
	}
}

func TestSudoRuleNoCommands(t *testing.T) {
	file := sudoRuleObservation("/etc/sudoers.d/empty", "")
	result, err := NewSudoRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(result.Findings))
	}
}

func TestSudoRuleUnavailable(t *testing.T) {
	file := sudoRuleObservation("/etc/sudoers.d/app", "tester ALL=(root) /usr/bin/app")
	file.Status = models.StatusUnavailable
	result, err := NewSudoRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
