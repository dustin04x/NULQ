# M4 Detection Specification

**NULQ — M4 architecture & engineering blueprint**

This document specifies proposed M4 detection rules: ID, module, category, required
observation kinds, detection conditions, evidence requirements, severity/confidence
conditions, UNKNOWN conditions, false-positive/false-negative considerations, and
synthetic test scenarios.

**Gate note:** Rules that depend on the entity/relationship/correlation model are
blocked on M3.5 acceptance. New hardening rules (M4.3) are independent of M3.5.

## Design principles (repeated for clarity)

- A detection rule must not label a system vulnerable merely because a suspicious
  configuration exists.
- Distinguish configuration inventory from meaningful exposure from evidence-backed
  impact.
- HIGH/CRITICAL require evidence that plausibly crosses into root/equivalent authority.
- UNKNOWN never collapses to ALLOWED or CONFIRMED.
- Every rule documents its limitations.

---

## Existing rules (preserved, unchanged)

| Rule | Module | Category | Required kinds | Default severity | Conservative basis |
|---|---|---|---|---|---|
| NULQ-ID-001 | identity | privileged-membership | group_membership | LOW | Docker/podman/lxd/lxc/libvirt/disk = HIGH; wheel/sudo/admin/root = LOW (sudo policy not evaluated); adm/input = LOW/MEDIUM |
| NULQ-FS-001 | filesystem | suid-sgid | file | INFO | HIGH only for root-owned writable SUID executable without nosuid |
| NULQ-FS-002 | filesystem | permissions | directory, file | MEDIUM | HIGH only for replaceable root-owned SUID child without nosuid |
| NULQ-FS-003 | filesystem | path-hijack | path_entry | LOW | Empty/relative/writable PATH; no privileged consumer observed |
| NULQ-FS-004 | filesystem | mounts | file, directory, mount | INFO | Mount flags contextualize SUID executables/world-writable dirs |
| NULQ-PROC-001 | process | permissions | process | MEDIUM | Writable-parent executable replacement |
| NULQ-SYS-001 | system | kernel-hardening | sysctl | LOW | 12-parameter sysctl baseline |
| NULQ-SYS-002 | system | security-controls | security_control, system_info | LOW | MAC posture |

These rules are **not** modified by M4. M4 adds rules below.

---

## New rule: NULQ-SYS-003 — Process capability surface (M4.3)

**Rule ID:** `NULQ-SYS-003`
**Name:** Process capability surface
**Module:** system
**Category:** capabilities
**Required observation kinds:** `process.info`, `identity.execution_context`
**Required entities:** process (M4.1)
**Required relationships:** `process_runs_as` (M4.1)
**Default severity:** `INFO`
**Default confidence:** `MEDIUM`

### Detection conditions
For each process observation with an executable path:
- Read the process capability bounding/effective set (from `/proc/<pid>/Status` `CapEff`/`CapBnd`, read-only, never executed).
- Flag processes whose effective capability set includes capabilities that can bypass DAC or MAC (e.g., `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`, `CAP_SETPCAP`).

### Evidence requirements
- `process_euid` (effective UID).
- `exe_path` (executable path).
- Capability set observed (hex/decoded list).
- Mount nosuid/noexec context of the executable.

### Severity conditions
- `INFO` when a privileged capability is present but the process is unprivileged (euid != 0).
- `MEDIUM` when euid == 0 AND a privilege-bypassing capability is present AND mount nosuid is not confirmed absent.
- Never `HIGH` (capability presence ≠ exploit demonstrated).

### Confidence conditions
- `MEDIUM` when capability set and euid are observed.
- `LOW` when capability set is unreadable (UNKNOWN).
- Never increased by combining multiple processes.

### UNKNOWN conditions
- Capability set unreadable → capability findings omitted; euid known → an INFO
  "capability surface could not be fully evaluated" finding may be emitted with
  explicit UNKNOWN limitation.
- euid missing → rule skipped (insufficient identity).

### False-positive considerations
- CAP_SYS_ADMIN is broad; many legitimate system processes hold it. Severity stays
  INFO/MEDIUM with limitations explaining this.
- Capability bounding set may be smaller than effective set; NULQ reports what is
  observed, not inferred.

### False-negative considerations
- File capabilities (xattr `security.capability`) on executables are not read in M4.3
  (deferred; requires xattr collection).
- Capabilities of child processes / exec transitions not tracked.

### Synthetic test scenarios
1. **Positive:** process euid 0 with CapEff containing CAP_DAC_OVERRIDE → MEDIUM finding
   citing process + capability evidence.
2. **Negative:** process euid 1000 with CapEff empty → no finding.
3. **Unavailable:** /proc/<pid>/Status unreadable → no finding, observation status
   unavailable; rule reports skip reason.
4. **Unknown:** capability set present but unparseable → LOW INFO finding with UNKNOWN
   limitation, never ALLOWED.

---

## New rule: NULQ-SYS-004 — Seccomp profile presence (M4.3)

**Rule ID:** `NULQ-SYS-004`
**Name:** Seccomp profile presence
**Module:** system
**Category:** sandboxing
**Required observation kinds:** `process.info`
**Default severity:** `INFO`
**Default confidence:** `LOW`

### Detection conditions
For each process, check `/proc/<pid>/status` `Seccomp` field:
- `0` (disabled) / `1` (filter) / `2` (strict).
- Flag processes in seccomp disabled mode that also run with euid == 0 (defence-in-depth gap).

### Evidence requirements
- `process_pid`, `process_euid`, `exe_path`.
- Seccomp mode observed.

### Severity conditions
- `INFO` when seccomp disabled AND euid == 0.
- `INFO` when seccomp filter mode (context only, not a weakness).
- No finding when seccomp strict.

### Confidence conditions
- `LOW` (seccomp mode is a single observable flag; low confidence in its security
  implication by design).
- Never `MEDIUM`/`HIGH` (seccomp absence ≠ exploit).

### UNKNOWN conditions
- `/proc/<pid>/status` unreadable → observation unavailable; rule skipped for that
  process; never assume seccomp state.

### False-positive considerations
- Many unprivileged processes run with seccomp disabled legitimately. Severity INFO
  only, no escalation without euid==0.

### Synthetic test scenarios
1. **Positive:** euid 0, seccomp=0 → INFO finding.
2. **Negative:** euid 0, seccomp=2 → no finding.
3. **Negative:** euid 1000, seccomp=0 → no finding (unprivileged).
4. **Unavailable:** status file missing → no finding for that process.

---

## New rule: NULQ-SYS-005 — Systemd unit security directives (M4.3)

**Rule ID:** `NULQ-SYS-005`
**Name:** Systemd unit lacks security hardening directives
**Module:** system
**Category:** service-hardening
**Required observation kinds:** `system.systemd_unit` (new kind, M4.3)
**Default severity:** `LOW`
**Default confidence:** `MEDIUM`

### Detection conditions
Read systemd unit files (read-only filesystem read, no D-Bus, no service execution):
- Check for `ProtectSystem=yes`, `ProtectHome=yes`, `NoNewPrivileges=yes`,
  `PrivateTmp=yes`, `CapabilityBoundingSet=`.
- Flag units running as root (User= root or unset) lacking `NoNewPrivileges=yes`.

### Evidence requirements
- Unit file path, `User=`, `NoNewPrivileges=`, `ProtectSystem=`, observed values.
- Whether unit is enabled/active is NOT read (no D-Bus); finding states this limitation.

### Severity conditions
- `LOW` when root-run unit lacks `NoNewPrivileges=yes`.
- `INFO` when unit lacks `ProtectSystem=` (context only).

### Confidence conditions
- `MEDIUM` when unit file read successfully.
- `LOW` when unit file unreadable (UNKNOWN; finding not emitted for that unit).

### UNKNOWN conditions
- Unit file unreadable → skip unit, observation unavailable.
- Whether unit is actually active → UNKNOWN; finding states "unit file inspected;
  runtime activation state not evaluated."

### False-positive considerations
- A unit lacking hardening directives may be intentionally unhardened for a workload.
- Severity LOW reflects this; finding is advisory.

### Synthetic test scenarios
1. **Positive:** unit file, User=root, no NoNewPrivileges → LOW finding.
2. **Negative:** User=root, NoNewPrivileges=yes → no finding.
3. **Negative:** User=nobody, no NoNewPrivileges → no finding (not root-run).
4. **Unavailable:** unit file unreadable → no finding for that unit.

---

## New rule: NULQ-SYS-006 — Unprivileged user namespace clone (M4.3)

**Rule ID:** `NULQ-SYS-006`
**Name:** Unprivileged user namespace clone enabled
**Module:** system
**Category:** kernel-hardening
**Required observation kinds:** `system.sysctl`
**Default severity:** `INFO`
**Default confidence:** `HIGH`

### Detection conditions
- `kernel.unprivileged_userns_clone` != 0 (where the sysctl exists on the kernel).
- Note: this parameter already appears in the NULQ-SYS-001 baseline as `INFO` with
  expected `0`. NULQ-SYS-006 is a dedicated, more prominent rule; the two are
  complementary not duplicative. (Design decision: de-duplicate by having NULQ-SYS-006
  reference the same observation; aggregation dedups identical resource+title.)

### Evidence requirements
- `kernel.unprivileged_userns_clone` value observed.
- Whether the kernel exposes the sysctl at all (absent → no finding, not assumed).

### Severity conditions
- `INFO` when value != 0.
- No finding when value == 0 or sysctl absent.

### Confidence conditions
- `HIGH` (direct kernel parameter observation).

### UNKNOWN conditions
- Sysctl absent from kernel → no finding (cannot assume disabled or enabled).
- Value unreadable → observation unavailable; rule skipped.

### Synthetic test scenarios
1. **Positive:** value=1 → INFO finding.
2. **Negative:** value=0 → no finding.
3. **Absent:** sysctl not present → no finding (not assumed).

---

## Correlated findings (M4.2 — blocked on M3.5)

Correlation scenarios produce findings (not just relationships). Specified here for
design completeness; implemented only after M3.5 acceptance.

### COR-001 correlated finding: Executable replacement exposure
**Rule ID:** `COR-001` (scenario)
**Required:** process, file, directory, mount, execution_context
**Severity:** HIGH only when ALL confirmed: replaceable parent + root-owned SUID +
  process running it with euid 0 + mount without nosuid/noexec. Otherwise MEDIUM
  (potential) or INFO/LOW.
**Confidence:** weakest-link minimum of constituent evidence.
**UNKNOWN:** mount state unknown → cap at MEDIUM with limitation; never HIGH.

### COR-002 correlated finding: Effective permission disagreement
**Rule ID:** `COR-002`
**Required:** file, directory, execution_context
**Severity:** INFO/LOW when mode bits and ACL disagree on effective write/exec for the
  assessed identity.
**Confidence:** MEDIUM when both mode and ACL observed; LOW when ACL unknown.
**UNKNOWN:** ACL unreadable → findings cite UNKNOWN limitation; never claim write allowed.

### COR-003 correlated finding: Mount security context
**Rule ID:** `COR-003`
**Required:** file, directory, mount
**Severity:** INFO (contextual; mount flags constrain but do not prove safety).
**Confidence:** depends on mount metadata completeness.

### COR-004 correlated finding: Shared exposure dedup
**Rule ID:** `COR-004`
**Required:** file, directory, process, mount
**Severity:** not assigned independently; used to deduplicate / merge related findings.
**Confidence:** not applied; structural.

### COR-005 correlated finding: Evidence-backed privilege-boundary assessment
**Rule ID:** `COR-005`
**Required:** process, file, directory, mount, execution_context
**Severity:** combines confirmed/potential/insufficient/contradicted/unknown; HIGH only
  for confirmed boundary crossing with evidence.
**Confidence:** never promoted by accumulation of low-confidence observations.

### Severity/confidence aggregation rules (M4.2)
- Correlated finding severity = `max(constituent severities)`, capped by highest
  `EvaluationConfirmed` constituent.
- Correlated finding confidence = `min(constituent confidences)`.
- `EvaluationConfirmed` + HIGH constituent → HIGH.
- `EvaluationPotential` → max MEDIUM.
- `EvaluationInsufficient`/`EvaluationUnknown` → max INFO/LOW with explicit limitation.

---

## Rule registration

All rules (existing + new) are registered explicitly in `internal/rules/rules.go`
`All()`. No discovery-based loading. `RuleMetadata.Validate()` requires non-empty ID,
version, name, description, category, module, valid severity/confidence, non-empty
`Required`, non-empty `Platforms`.

### Proposed M4 registration order
```
NULQ-ID-001 (identity)
NULQ-FS-001..004 (filesystem)
NULQ-PROC-001 (process)
NULQ-SYS-001..006 (system)
COR-001..005 (correlation, M4.2, blocked on M3.5)
```

## Validation requirements for every M4 rule

1. Stable ID `NULQ-<AREA>-<NNN>` or `COR-<NNN>` and semantic version in metadata.
2. Precise `Required` observation kinds; engine skips when prerequisites absent and
   records the reason.
3. Every claim supported by evidence from the shared store.
4. Positive, negative, and unavailable-data tests, including severity boundary cases.
5. Explicit registration in `internal/rules/rules.go`.
6. Explanation, impact, remediation, limitations written for a reviewer who will not
   re-run the scan.
7. Changelog entry.
8. Lab coverage: scenario proving the rule fires on the fixture and stays silent on
   the negative control, or explicit statement of why not lab-testable.
