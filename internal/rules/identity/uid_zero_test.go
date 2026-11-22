package identity

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func userAccountObs(name, uid, shell, home string) models.Observation {
	obs := models.NewObservation(models.KindUserAccount, "user:"+name, "test", time.Now(), nil)
	obs.Set(models.AttrUserName, name)
	obs.Set(models.AttrUserUID, uid)
	obs.Set(models.AttrUserShell, shell)
	if home != "" {
		obs.Set(models.AttrUserHome, home)
	}
	return obs
}

func TestUIDZeroRuleNonRootUIDZero(t *testing.T) {
	obs := userAccountObs("toor", "0", "/bin/bash", "/root")
	result, err := NewUIDZeroRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityHigh {
		t.Fatalf("severity = %s, want HIGH", result.Findings[0].Severity)
	}
}

func TestUIDZeroRuleRootIsSilent(t *testing.T) {
	obs := userAccountObs("root", "0", "/bin/bash", "/root")
	result, err := NewUIDZeroRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for root, got %d", len(result.Findings))
	}
}

func TestUIDZeroRuleNonZeroUIDIsSilent(t *testing.T) {
	obs := userAccountObs("app", "1001", "/bin/bash", "/home/app")
	result, err := NewUIDZeroRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for non-root UID, got %d", len(result.Findings))
	}
}

func TestUIDZeroRuleUnavailableIsSkipped(t *testing.T) {
	obs := models.UnavailableObservation(models.KindUserAccount, "user:toor", "test", time.Now(),
		models.ObservationError{Class: "permission_denied", Message: "cannot read /etc/passwd"})
	result, err := NewUIDZeroRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
