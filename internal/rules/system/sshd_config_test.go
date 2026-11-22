package system

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func sshdConfigObs(path string, directives map[string]string) models.Observation {
	obs := models.NewObservation(models.KindSSHDConfig, path, "test", time.Now(), nil)
	var lines []string
	for k, v := range directives {
		lines = append(lines, k+"="+v)
		obs.Set(models.AttrSSHDirective+"."+k, v)
	}
	obs.Set(models.AttrSSHDirective, stringsJoin(lines, "\n"))
	return obs
}

func stringsJoin(values []string, sep string) string {
	var result string
	for i, v := range values {
		if i > 0 {
			result += sep
		}
		result += v
	}
	return result
}

func TestSSHDConfigRulePermitRootLoginYes(t *testing.T) {
	obs := sshdConfigObs("/etc/ssh/sshd_config", map[string]string{
		"permitrootlogin": "yes",
	})
	result, err := NewSSHDConfigRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
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

func TestSSHDConfigRulePasswordAuthYes(t *testing.T) {
	obs := sshdConfigObs("/etc/ssh/sshd_config", map[string]string{
		"passwordauthentication": "yes",
	})
	result, err := NewSSHDConfigRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
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

func TestSSHDConfigRuleX11ForwardingYes(t *testing.T) {
	obs := sshdConfigObs("/etc/ssh/sshd_config", map[string]string{
		"x11forwarding": "yes",
	})
	result, err := NewSSHDConfigRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
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

func TestSSHDConfigRuleSecureIsSilent(t *testing.T) {
	obs := sshdConfigObs("/etc/ssh/sshd_config", map[string]string{
		"permitrootlogin":        "no",
		"passwordauthentication": "no",
		"x11forwarding":          "no",
	})
	result, err := NewSSHDConfigRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for secure config, got %d", len(result.Findings))
	}
}

func TestSSHDConfigRuleUnavailableIsSkipped(t *testing.T) {
	obs := models.UnavailableObservation(models.KindSSHDConfig, "/etc/ssh/sshd_config", "test", time.Now(),
		models.ObservationError{Class: "not_found", Message: "no sshd_config"})
	result, err := NewSSHDConfigRule().Evaluate(context.Background(), store.New([]models.Observation{obs}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("want 0 findings for unavailable observation, got %d", len(result.Findings))
	}
}
