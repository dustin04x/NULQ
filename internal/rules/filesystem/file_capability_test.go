package filesystem

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func fileCapabilityObservation(path string, permitted, inheritable, effective string) models.Observation {
	obs := models.NewObservation(models.KindFile, path, "test", time.Now(), nil)
	if permitted != "" {
		obs.Set(models.AttrFileCapPermitted, permitted)
	}
	if inheritable != "" {
		obs.Set(models.AttrFileCapInheritable, inheritable)
	}
	if effective != "" {
		obs.Set(models.AttrFileCapEffective, effective)
	}
	obs.Set(models.AttrMode, "0755")
	obs.Set(models.AttrSetUID, "false")
	obs.Set(models.AttrSetGID, "false")
	obs.Set(models.AttrOwnerUID, "0")
	obs.Set(models.AttrOwnerUser, "root")
	obs.Set(models.AttrWritableByCurrentUser, "false")
	return obs
}

func TestFileCapabilityRulePositive(t *testing.T) {
	file := fileCapabilityObservation("/usr/bin/privileged-tool", "00000004", "00000000", "00000000")
	result, err := NewFileCapabilityRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityMedium {
		t.Fatalf("severity = %s, want MEDIUM", result.Findings[0].Severity)
	}
	if len(result.Findings[0].Evidence) == 0 {
		t.Fatal("finding must cite evidence")
	}
}

func TestFileCapabilityRuleUnprivileged(t *testing.T) {
	file := fileCapabilityObservation("/usr/bin/privileged-tool", "00000004", "00000000", "00000000")
	file.Set(models.AttrOwnerUID, "1000")
	file.Set(models.AttrOwnerUser, "tester")
	result, err := NewFileCapabilityRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
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

func TestFileCapabilityRuleNoCapabilities(t *testing.T) {
	file := fileCapabilityObservation("/usr/bin/plain-tool", "", "", "")
	result, err := NewFileCapabilityRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(result.Findings))
	}
}

func TestFileCapabilityRuleAbsentAttributes(t *testing.T) {
	obs := models.NewObservation(models.KindFile, "/usr/bin/plain-tool", "test", time.Now(), nil)
	obs.Set(models.AttrMode, "0755")
	obs.Set(models.AttrSetUID, "false")
	obs.Set(models.AttrSetGID, "false")
	obs.Set(models.AttrOwnerUID, "0")
	obs.Set(models.AttrOwnerUser, "root")
	result, err := NewFileCapabilityRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(result.Findings))
	}
}
