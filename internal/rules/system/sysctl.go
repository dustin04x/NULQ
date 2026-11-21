// Package system contains rules about kernel and platform hardening.
package system

import (
	"context"
	"strconv"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

type sysctlRule struct{}

// NewSysctlRule constructs the rule.
func NewSysctlRule() interfaces.Rule { return sysctlRule{} }

// Metadata implements interfaces.Rule.
func (r sysctlRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-SYS-001",
		Version:     "1.0.0",
		Name:        "Kernel sysctl hardening baseline",
		Description: "A security-relevant kernel parameter is set below a conservative baseline, expanding the attack surface available to unprivileged users.",
		Category:    "kernel-hardening",
		Module:      "system",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindSysctl},
		Platforms:   []string{"linux"},
	}
}

// sysctlBaseline describes one parameter expectation.
type sysctlBaseline struct {
	key         string
	expected    string
	severity    models.Severity
	rationale   string
	remediation string
	ok          func(string) bool
}

// sysctlBaselines is a conservative, documented baseline. Parameters absent
// from the kernel are skipped, never assumed to be secure.
var sysctlBaselines = []sysctlBaseline{
	{
		key: "kernel.kptr_restrict", expected: "at least 1", severity: models.SeverityLow,
		rationale:   "Kernel pointers are exposed through several interfaces; unrestricted values aid exploit development.",
		remediation: "Set kernel.kptr_restrict=1 or 2 in /etc/sysctl.d/.",
		ok:          intAtLeast(1),
	},
	{
		key: "kernel.dmesg_restrict", expected: "1", severity: models.SeverityLow,
		rationale:   "Unprivileged reads of the kernel ring buffer can disclose addresses and system state.",
		remediation: "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/.",
		ok:          intEquals(1),
	},
	{
		key: "kernel.yama.ptrace_scope", expected: "at least 1", severity: models.SeverityLow,
		rationale:   "Yama scope above zero restricts ptrace to descendants, limiting credential theft from unrelated processes.",
		remediation: "Set kernel.yama.ptrace_scope=1 in /etc/sysctl.d/.",
		ok:          intAtLeast(1),
	},
	{
		key: "kernel.perf_event_paranoid", expected: "at least 2", severity: models.SeverityLow,
		rationale:   "Permissive perf events allow unprivileged users to sample kernel and other processes' execution.",
		remediation: "Set kernel.perf_event_paranoid=2 or higher in /etc/sysctl.d/.",
		ok:          intAtLeast(2),
	},
	{
		key: "kernel.unprivileged_bpf_disabled", expected: "at least 1", severity: models.SeverityLow,
		rationale:   "Unprivileged BPF program loading has been a recurring source of kernel privilege-escalation primitives.",
		remediation: "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/ or at boot.",
		ok:          intAtLeast(1),
	},
	{
		key: "kernel.randomize_va_space", expected: "2", severity: models.SeverityLow,
		rationale:   "Full address-space layout randomisation raises the reliability cost of memory-corruption exploitation.",
		remediation: "Set kernel.randomize_va_space=2 in /etc/sysctl.d/.",
		ok:          intEquals(2),
	},
	{
		key: "kernel.suid_dumpable", expected: "0", severity: models.SeverityLow,
		rationale:   "Core dumps from set-user-ID processes can contain sensitive memory from an elevated context.",
		remediation: "Set kernel.suid_dumpable=0 in /etc/sysctl.d/.",
		ok:          intEquals(0),
	},
	{
		key: "fs.protected_hardlinks", expected: "1", severity: models.SeverityLow,
		rationale:   "Without hardlink protection, a user can link to files they cannot write and exploit privileged writers.",
		remediation: "Set fs.protected_hardlinks=1 in /etc/sysctl.d/.",
		ok:          intEquals(1),
	},
	{
		key: "fs.protected_symlinks", expected: "1", severity: models.SeverityLow,
		rationale:   "Without symlink protection, world-writable sticky directories enable symlink-following attacks against privileged writers.",
		remediation: "Set fs.protected_symlinks=1 in /etc/sysctl.d/.",
		ok:          intEquals(1),
	},
	{
		key: "fs.protected_fifos", expected: "at least 1", severity: models.SeverityInfo,
		rationale:   "FIFO protection blocks a class of writes into privileged processes through pre-created pipes.",
		remediation: "Set fs.protected_fifos=1 in /etc/sysctl.d/.",
		ok:          intAtLeast(1),
	},
	{
		key: "fs.protected_regular", expected: "at least 1", severity: models.SeverityInfo,
		rationale:   "Regular-file protection prevents privileged opens from following attacker-planted files in sticky directories.",
		remediation: "Set fs.protected_regular=1 in /etc/sysctl.d/.",
		ok:          intAtLeast(1),
	},
	{
		key: "kernel.unprivileged_userns_clone", expected: "0", severity: models.SeverityInfo,
		rationale:   "Unprivileged user namespaces widen the kernel surface reachable by unprivileged users on distributions that expose this switch.",
		remediation: "Set kernel.unprivileged_userns_clone=0 where the workload does not require unprivileged namespaces.",
		ok:          intEquals(0),
	},
}

// Evaluate implements interfaces.Rule.
func (r sysctlRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()

	byKey := make(map[string]models.Observation)
	for _, parameter := range obs.ByKind(models.KindSysctl) {
		byKey[parameter.Resource] = parameter
	}

	var findings []models.Finding
	for _, baseline := range sysctlBaselines {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		parameter, ok := byKey[baseline.key]
		if !ok || parameter.Status != models.StatusComplete {
			continue
		}
		value, ok := parameter.Attr(models.AttrValue)
		if !ok || value == "" {
			continue
		}
		if baseline.ok(value) {
			continue
		}

		finding := models.NewFinding(meta, baseline.key, models.ResourceSysctl,
			baseline.severity, models.ConfidenceHigh,
			"Kernel hardening parameter is below the recommended baseline", now)
		finding.Explanation = "The kernel parameter " + baseline.key + " is " + value +
			", which does not meet the baseline (" + baseline.expected + "). " + baseline.rationale
		finding.Impact = "The weaker setting expands what unprivileged local processes can observe or exercise in the kernel. " +
			"It is a hardening gap, not by itself a vulnerability."
		finding.Remediation = baseline.remediation
		finding.Limitations = []string{
			"Baselines are conservative defaults; some environments require different values for workload compatibility.",
			"This rule does not assess whether a known exploit applies to the running kernel.",
		}
		finding.AddEvidence(
			builder.AddExpected(parameter, models.AttrValue, baseline.expected, "Current kernel parameter value."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

func intAtLeast(minimum int) func(string) bool {
	return func(value string) bool {
		parsed, err := strconv.Atoi(value)
		return err == nil && parsed >= minimum
	}
}

func intEquals(want int) func(string) bool {
	return func(value string) bool {
		parsed, err := strconv.Atoi(value)
		return err == nil && parsed == want
	}
}
