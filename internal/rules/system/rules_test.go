package system

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func sysctlObservation(key, value string) models.Observation {
	obs := models.NewObservation(models.KindSysctl, key, "test", time.Now(), nil)
	obs.Set(models.AttrValue, value)
	return obs
}

func unavailableSysctl(key string) models.Observation {
	obs := models.NewObservation(models.KindSysctl, key, "test", time.Now(), nil)
	obs.Status = models.StatusUnavailable
	obs.Error = &models.ObservationError{Class: "not_found", Message: "parameter is not exposed"}
	return obs
}

func controlObservation(resource string, attributes map[string]string) models.Observation {
	return models.NewObservation(models.KindSecurityControl, resource, "test", time.Now(), attributes)
}

func systemInfoObservation(lsmList string) models.Observation {
	obs := models.NewObservation(models.KindSystemInfo, "host", "test", time.Now(), nil)
	if lsmList != "" {
		obs.Set(models.AttrLSMList, lsmList)
	}
	return obs
}

func TestSysctlRuleReportsOnlyDeviations(t *testing.T) {
	rule := NewSysctlRule()
	if err := rule.Metadata().Validate(); err != nil {
		t.Fatal(err)
	}

	weak := store.New([]models.Observation{
		sysctlObservation("kernel.kptr_restrict", "0"),
	})
	result, err := rule.Evaluate(context.Background(), weak)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding for a weak parameter, got %d", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Severity != models.SeverityLow || finding.Resource != "kernel.kptr_restrict" {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if got := result.Evidence[0].ObservedValue; got != "0" {
		t.Fatalf("evidence value = %q, want 0", got)
	}
	if result.Evidence[0].ExpectedValue == "" {
		t.Fatal("evidence must record the expected baseline")
	}

	hardened := store.New([]models.Observation{
		sysctlObservation("kernel.kptr_restrict", "2"),
		sysctlObservation("kernel.dmesg_restrict", "1"),
	})
	result, err = rule.Evaluate(context.Background(), hardened)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("compliant parameters must not produce findings: %+v", result.Findings)
	}
}

func TestSysctlRuleSkipsUnavailableParameters(t *testing.T) {
	result, err := NewSysctlRule().Evaluate(context.Background(),
		store.New([]models.Observation{unavailableSysctl("kernel.kptr_restrict")}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("an unreadable parameter must not be reported as a weakness: %+v", result.Findings)
	}
}

func TestMACRuleDetectsMissingControl(t *testing.T) {
	observations := store.New([]models.Observation{
		systemInfoObservation("capability,landlock,lockdown,yama,bpf"),
		controlObservation("lsm:capability", map[string]string{models.AttrActive: "true"}),
		controlObservation("lsm:yama", map[string]string{models.AttrActive: "true"}),
		controlObservation("apparmor", map[string]string{models.AttrActive: "false", models.AttrValue: "N"}),
	})

	result, err := NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Severity != models.SeverityLow {
		t.Fatalf("severity = %s, want LOW", result.Findings[0].Severity)
	}
	if len(result.Findings[0].Evidence) == 0 {
		t.Fatal("finding must cite evidence")
	}
}

func TestMACRuleDetectsPermissiveSELinux(t *testing.T) {
	observations := store.New([]models.Observation{
		systemInfoObservation("capability,selinux,yama"),
		controlObservation("lsm:selinux", map[string]string{models.AttrActive: "true"}),
		controlObservation("selinux", map[string]string{models.AttrActive: "true", models.AttrValue: "0", models.AttrDetail: "permissive"}),
	})
	result, err := NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want exactly one permissive finding, got %+v", result.Findings)
	}
	if result.Findings[0].Severity != models.SeverityMedium {
		t.Fatalf("severity = %s, want MEDIUM", result.Findings[0].Severity)
	}
}

func TestMACRuleKeepsEnforcementAcrossModules(t *testing.T) {
	// A permissive SELinux must not cancel an enforcing AppArmor, and the
	// generic "no MAC enforcing" finding must not appear alongside the
	// specific permissive finding.
	observations := store.New([]models.Observation{
		systemInfoObservation("capability,apparmor,selinux"),
		controlObservation("lsm:apparmor", map[string]string{models.AttrActive: "true"}),
		controlObservation("apparmor", map[string]string{models.AttrActive: "true"}),
		controlObservation("lsm:selinux", map[string]string{models.AttrActive: "true"}),
		controlObservation("selinux", map[string]string{models.AttrActive: "true", models.AttrValue: "0", models.AttrDetail: "permissive"}),
	})
	result, err := NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want exactly the permissive SELinux finding, got %+v", result.Findings)
	}
	if result.Findings[0].Resource != "selinux" || result.Findings[0].Severity != models.SeverityMedium {
		t.Fatalf("unexpected finding: %+v", result.Findings[0])
	}
}

func TestMACRuleUnknownAdvertisedModuleIsNotDisabled(t *testing.T) {
	// AppArmor is advertised by the kernel but no state observation exists.
	// That is unknown, not disabled, so no weakness may be claimed.
	observations := store.New([]models.Observation{
		systemInfoObservation("capability,apparmor,yama"),
		controlObservation("lsm:apparmor", map[string]string{models.AttrActive: "true"}),
	})
	result, err := NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("unknown AppArmor state must not produce a finding: %+v", result.Findings)
	}

	// Same for SELinux: advertised with no usable enforcement detail.
	observations = store.New([]models.Observation{
		systemInfoObservation("capability,selinux,yama"),
		controlObservation("lsm:selinux", map[string]string{models.AttrActive: "true"}),
		controlObservation("selinux", map[string]string{models.AttrActive: "true"}),
	})
	result, err = NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("unknown SELinux state must not produce a finding: %+v", result.Findings)
	}

	// smack has no state collector; advertisement alone proves nothing.
	observations = store.New([]models.Observation{
		systemInfoObservation("capability,smack"),
		controlObservation("lsm:smack", map[string]string{models.AttrActive: "true"}),
	})
	result, err = NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("advertised smack without state must not produce a finding: %+v", result.Findings)
	}
}

func TestMACRuleAppArmorAloneIsSilent(t *testing.T) {
	observations := store.New([]models.Observation{
		systemInfoObservation("capability,apparmor,yama"),
		controlObservation("lsm:apparmor", map[string]string{models.AttrActive: "true"}),
		controlObservation("apparmor", map[string]string{models.AttrActive: "true"}),
	})
	result, err := NewMACRule().Evaluate(context.Background(), observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("enforcing AppArmor must not produce findings: %+v", result.Findings)
	}
}

func TestMACRuleStaysSilentWhenEnforcingOrUnknown(t *testing.T) {
	enforcing := store.New([]models.Observation{
		systemInfoObservation("capability,selinux,yama"),
		controlObservation("lsm:selinux", map[string]string{models.AttrActive: "true"}),
		controlObservation("selinux", map[string]string{models.AttrActive: "true", models.AttrValue: "1", models.AttrDetail: "enforcing"}),
	})
	result, err := NewMACRule().Evaluate(context.Background(), enforcing)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("enforcing SELinux must not produce findings: %+v", result.Findings)
	}

	unknown := store.New([]models.Observation{
		systemInfoObservation(""),
		controlObservation("lsm:list", map[string]string{models.AttrActive: "false"}),
	})
	result, err = NewMACRule().Evaluate(context.Background(), unknown)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("unknown LSM state must not be reported as a weakness: %+v", result.Findings)
	}
}
