package system

import (
	"context"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type macRule struct{}

// NewMACRule constructs the rule.
func NewMACRule() interfaces.Rule { return macRule{} }

// Metadata implements interfaces.Rule.
func (r macRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-002",
		Version:     "1.0.0",
		Name:        "Mandatory access control posture",
		Description: "No mandatory access control module is enforcing, or a module is present but not enforcing, so kernel-level confinement does not constrain compromised privileged processes.",
		Category:    "security-controls",
		Module:      "system",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindSecurityControl, models.KindSystemInfo},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
//
// Enforcement is taken from each module's own state observation, never from
// membership in the kernel's LSM list (a listed module can be permissive or
// disabled). Enforcement by one module is not cancelled by another module
// being permissive.
func (r macRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	lsmKnown := false
	var infoObs models.Observation
	for _, info := range obs.ByKind(models.KindSystemInfo) {
		infoObs = info
		if _, ok := info.Attr(models.AttrLSMList); ok {
			lsmKnown = true
		}
	}

	enforcing := false
	permissiveSELinux := false
	macAdvertised := false
	macStateUnavailable := false
	advertised := map[string]bool{}
	apparmor, haveAppArmor := models.Observation{}, false
	selinux, haveSELinux := models.Observation{}, false

	for _, control := range obs.ByKind(models.KindSecurityControl) {
		switch {
		case control.Resource == "apparmor":
			apparmor, haveAppArmor = control, true
			macAdvertised = true
			if control.Bool(models.AttrActive) {
				enforcing = true
			}
		case control.Resource == "selinux":
			selinux, haveSELinux = control, true
			macAdvertised = true
			mode, _ := control.Attr(models.AttrDetail)
			switch mode {
			case "enforcing":
				enforcing = true
			case "permissive":
				permissiveSELinux = true
			case "":
				macStateUnavailable = true
			default:
				macStateUnavailable = true
			}
		case control.Resource == "lsm:list":
			continue
		default:
			if name, ok := strings.CutPrefix(control.Resource, "lsm:"); ok && control.Bool(models.AttrActive) && isMACModule(name) {
				// Advertisement only; enforcement needs the module's state file.
				macAdvertised = true
				advertised[name] = true
			}
		}
	}

	// A module can be advertised without a usable state observation. Treat
	// that as unknown, never as disabled. smack has no state collector at all.
	if advertised["apparmor"] && !haveAppArmor {
		macStateUnavailable = true
	}
	if advertised["selinux"] && !haveSELinux {
		macStateUnavailable = true
	}
	if advertised["smack"] {
		macStateUnavailable = true
	}

	var findings []models.Finding

	if haveSELinux && permissiveSELinux {
		finding := models.NewFinding(meta, "selinux", models.ResourceSecurityControl,
			models.SeverityMedium, models.ConfidenceHigh,
			"SELinux is running in permissive mode", now)
		finding.Explanation = "SELinux is loaded but logs policy violations instead of denying them. " +
			"The module provides no confinement while in this state."
		finding.Impact = "A compromised service is not constrained by the SELinux policy, reducing defence in depth. Other modules may still enforce."
		finding.Remediation = "Set SELinux to enforcing (setenforce 1, then persist via /etc/selinux/config) after resolving policy denials."
		finding.Limitations = []string{
			"Policy content, loaded modules and per-domain booleans are not assessed.",
			"Only the global enforcement state is read; per-domain permissive settings are not evaluated.",
		}
		finding.AddEvidence(
			builder.Add(selinux, models.AttrDetail, "Observed SELinux enforcement state."),
			builder.Add(selinux, models.AttrValue, "Raw enforcement flag read from sysfs."),
		)
		findings = append(findings, finding)
	}

	if !enforcing && !permissiveSELinux && !macStateUnavailable && lsmKnown {
		finding := models.NewFinding(meta, "security-controls", models.ResourceSecurityControl,
			models.SeverityLow, models.ConfidenceMedium,
			"No mandatory access control module is enforcing", now)
		finding.Explanation = "The kernel does not report an enforcing mandatory access control module. " +
			"Discretionary ownership and permission bits are then the only confinement boundary."
		if macAdvertised {
			finding.Explanation = "A mandatory access control module is present in the kernel LSM list but is not enforcing. " +
				"Discretionary ownership and permission bits are then the only confinement boundary."
		}
		finding.Impact = "A compromised privileged process is constrained only by DAC, which it usually bypasses."
		finding.Remediation = "Enable AppArmor or SELinux with an enforcing profile set appropriate to the workload."
		finding.Limitations = []string{
			"NULQ checks advertised LSM presence and the SELinux/AppArmor state files; profile coverage per service is not assessed.",
			"Landlock, Yama and BPF are not mandatory access control modules and do not satisfy this baseline.",
			"A module whose state file is unreadable is treated as unknown: no finding is produced from missing state.",
		}
		finding.AddEvidence(builder.Add(infoObs, models.AttrLSMList, "Security modules advertised by the running kernel."))
		if haveAppArmor {
			finding.AddEvidence(builder.Add(apparmor, models.AttrActive, "Whether AppArmor reports itself enabled."))
		}
		if haveSELinux {
			finding.AddEvidence(builder.Add(selinux, models.AttrDetail, "Observed SELinux state."))
		}
		findings = append(findings, finding)
	}

	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

func isMACModule(name string) bool {
	switch name {
	case "selinux", "apparmor", "smack":
		return true
	}
	return false
}
