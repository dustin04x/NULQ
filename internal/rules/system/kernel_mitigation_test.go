package system

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func kernelMitigationObservation(name string, value string, status string) models.Observation {
	obs := models.NewObservation(models.KindKernelMitigation, name, "test", time.Now(), nil)
	if value != "" {
		obs.Set(models.AttrMitigationValue, value)
	}
	if status != "" {
		obs.Set(models.AttrMitigationStatus, status)
	}
	return obs
}

func TestKernelMitigationRuleVulnerable(t *testing.T) {
	mit := kernelMitigationObservation("spectre_v2", "Vulnerable", "vulnerable")
	result, err := NewKernelMitigationRule().Evaluate(context.Background(), store.New([]models.Observation{mit}))
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

func TestKernelMitigationRulePartial(t *testing.T) {
	mit := kernelMitigationObservation("l1tf", "Mitigation: PTE Inversion", "mitigation_partial")
	result, err := NewKernelMitigationRule().Evaluate(context.Background(), store.New([]models.Observation{mit}))
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

func TestKernelMitigationRuleNotAffected(t *testing.T) {
	mit := kernelMitigationObservation("meltdown", "Not affected", "not_affected")
	result, err := NewKernelMitigationRule().Evaluate(context.Background(), store.New([]models.Observation{mit}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for not_affected, got %d", len(result.Findings))
	}
}

func TestKernelMitigationRuleUnavailable(t *testing.T) {
	mit := kernelMitigationObservation("spectre_v2", "Vulnerable", "vulnerable")
	mit.Status = models.StatusUnavailable
	result, err := NewKernelMitigationRule().Evaluate(context.Background(), store.New([]models.Observation{mit}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
