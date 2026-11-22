package identity

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func authorizedKeysObs(path, writable string) models.Observation {
	obs := models.NewObservation(models.KindSSHAuthorizedKeys, path, "test", time.Now(), nil)
	obs.Set(models.AttrAuthKeysPath, path)
	obs.Set(models.AttrAuthKeysWritable, writable)
	return obs
}

func TestAuthorizedKeysRuleWritable(t *testing.T) {
	obs := authorizedKeysObs("/home/user/.ssh/authorized_keys", "true")
	result, err := NewAuthorizedKeysRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
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

func TestAuthorizedKeysRuleNotWritableIsSilent(t *testing.T) {
	obs := authorizedKeysObs("/home/user/.ssh/authorized_keys", "false")
	result, err := NewAuthorizedKeysRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for non-writable, got %d", len(result.Findings))
	}
}

func TestAuthorizedKeysRuleUnavailableIsSkipped(t *testing.T) {
	obs := models.UnavailableObservation(models.KindSSHAuthorizedKeys, "/home/user/.ssh/authorized_keys", "test", time.Now(),
		models.ObservationError{Class: "permission_denied", Message: "cannot stat"})
	result, err := NewAuthorizedKeysRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
