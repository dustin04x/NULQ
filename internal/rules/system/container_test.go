package system

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func containerIndicatorObservation(resource string, dockerSocket string, containerMount string) models.Observation {
	obs := models.NewObservation(models.KindContainerIndicator, resource, "test", time.Now(), nil)
	if dockerSocket != "" {
		obs.Set(models.AttrDockerSocket, dockerSocket)
	}
	if containerMount != "" {
		obs.Set(models.AttrContainerMount, containerMount)
	}
	return obs
}

func TestContainerIndicatorRuleDockerSocket(t *testing.T) {
	file := containerIndicatorObservation("/var/run/docker.sock", "true", "")
	result, err := NewContainerIndicatorRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
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

func TestContainerIndicatorRuleMarkerFile(t *testing.T) {
	file := containerIndicatorObservation("/.dockerenv", "", "true")
	result, err := NewContainerIndicatorRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityInfo {
		t.Fatalf("severity = %s, want INFO", result.Findings[0].Severity)
	}
}

func TestContainerIndicatorRuleUnavailable(t *testing.T) {
	file := containerIndicatorObservation("/var/run/docker.sock", "true", "")
	file.Status = models.StatusUnavailable
	result, err := NewContainerIndicatorRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
