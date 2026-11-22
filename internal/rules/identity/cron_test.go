package identity

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func cronJobObservation(path string, commands string, writable string) models.Observation {
	obs := models.NewObservation(models.KindCronJob, path, "test", time.Now(), nil)
	if commands != "" {
		obs.Set(models.AttrCronCommand, commands)
	}
	if writable != "" {
		obs.Set(models.AttrWritableByCurrentUser, writable)
	}
	return obs
}

func TestCronRuleWritable(t *testing.T) {
	file := cronJobObservation("/etc/cron.d/backup", "0 2 * * * root /usr/local/bin/backup.sh", "allowed")
	result, err := NewCronRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
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

func TestCronRuleNotWritable(t *testing.T) {
	file := cronJobObservation("/etc/cron.d/backup", "0 2 * * * root /usr/local/bin/backup.sh", "denied")
	result, err := NewCronRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
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

func TestCronRuleNoCommands(t *testing.T) {
	file := cronJobObservation("/etc/cron.d/empty", "", "false")
	result, err := NewCronRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(result.Findings))
	}
}

func TestCronRuleUnavailable(t *testing.T) {
	file := cronJobObservation("/etc/cron.d/backup", "0 2 * * * root /usr/local/bin/backup.sh", "allowed")
	file.Status = models.StatusUnavailable
	result, err := NewCronRule().Evaluate(context.Background(), store.New([]models.Observation{file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
