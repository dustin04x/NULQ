# M4 Red-Team Review

**NULQ — Independent adversarial review of the M4 engineering blueprint**

**Reviewer role:** Independent architecture challenge. This review exists to challenge
every important assumption, not to agree with the architecture author.

**Scope:** Documentation-only review of the M4 blueprint documents in
`docs/roadmap/` against the actual repository source code. No Go source, tests,
schemas, CI, or CLI behavior was modified as part of this review.

**Classification scale:**
- **BLOCKER** — design cannot proceed until resolved
- **MAJOR** — significant design flaw requiring correction before implementation
- **MODERATE** — design weakness that should be corrected but does not block
- **MINOR** — cosmetic or low-impact issue

---

## Baseline findings

### BF-1 — M3.5 acceptance is completely absent (BLOCKER)

**Source:** `docs/audits/` contains only M1.5 and M2 acceptance documents. No
`docs/audits/m35-*` document exists.

**Explanation:** The M4 blueprint (`M4-ENGINEERING-BLUEPRINT.md:9-27`) correctly
states that M3.5 was not completed and no M3.5 acceptance documents exist. This is
verified: `docs/audits/` lists m1.5-baseline, m1.5-security-corrections,
m1.5-independent-source-review, m1.5-final-acceptance, m1.5-final-engineering-report,
m2-baseline, m2-architecture-review, m2-independent-acceptance-audit,
m2-verification-evidence, m2-final-engineering-report. Zero M3.5 documents.

**Consequence:** M4.1 (entity model + relationship graph) and M4.2 (correlation
findings + aggregation) are blocked on M3.5 acceptance per
`m4-implementation-plan.md:14-19`. These stages cannot be implemented, tested, or
accepted until M3.5 reaches a documented verdict.

**Recovery requirement:** M3.5 must be completed and accepted (or explicitly rejected
with a remediation plan) before M4.1/M4.2 can proceed. M4.0 (foundations gate) cannot
issue a "go" decision without an M3.5 verdict.

---

### BF-2 — Working tree contains uncommitted M4 implementation code (MAJOR)

**Source:** `git status --short` shows 15 modified files and 9 untracked files,
including `internal/core/models/severity.go`, `internal/engine/executor/executor.go`,
`internal/engine/correlation/`, `internal/rules/system/capabilities.go`,
`internal/rules/system/seccomp.go`, `internal/rules/system/systemd.go`,
`internal/rules/system/userns.go`, `internal/platform/linux/systemd/`,
`internal/app/app.go`, `internal/cli/scan.go`, `tests/integration/correlation_test.go`.

**Explanation:** The blueprint claims "Nothing here modifies Go source, tests, schemas,
CLI behavior, dependencies, or CI" (`M4-ENGINEERING-BLUEPRINT.md:80-81`), but the
working tree contradicts this. M4.3 code (4 new rules), M4.4 code
(`--deterministic` flag, deterministic serialization), a systemd collector, and
modifications to `severity.go`, `executor.go`, `attributes.go`, `observation.go`,
`evidence.go`, `process/collector.go`, `rules.go`, `app.go`, `scan.go`, and
`cli_test.go` are all present as uncommitted changes.

**Consequence:** The blueprint documents do not describe the actual repository state.
Reviewers cannot trust that "documentation-only" means what it says. Any red-team
review must evaluate the code that actually exists, not just the documents.

---

### BF-3 — Correlation engine is untracked, untested, and not in CI (BLOCKER)

**Source:** `internal/engine/correlation/engine.go` (801 lines) and
`internal/engine/correlation/scenarios/scenarios.go` (172 lines) are untracked.
`tests/integration/correlation_test.go` is untracked and is a debug-style smoke test
with `t.Logf` statements and no real assertions beyond "at least one COR-001
relationship exists." No unit tests exist for the correlation package.

**Explanation:** The correlation engine is wired into `executor.Run()` via uncommitted
changes to `internal/engine/executor/executor.go:140-141` (`result.Correlation =
corrEngine.Run()`), but it is not part of any accepted milestone, has zero test
coverage, is not in CI, and produces relationships only — not findings. M4.2 assumes
the correlation engine will emit `models.Finding` values, but the current engine
produces `[]Relationship` only.

**Consequence:** M4.2 cannot be implemented on top of the current correlation engine.
The engine must be accepted by M3.5 first, then extended to emit findings. M4.2's
dependency on M3.5 is correctly identified but the severity of the block is
understated in the blueprint.

---

### BF-4 — `EvaluationOutcome` is duplicated between committed and untracked code (MAJOR)

**Source:** `internal/core/models/severity.go:12-67` (committed, defines
`EvaluationOutcome`) and `internal/engine/correlation/engine.go:42-95` (untracked,
redefines the same type with identical values and methods).

**Explanation:** The same type exists in two places with no relationship between them.
The committed version is used by nothing (no rule or aggregation references it). The
untracked version is used by the correlation engine. If M3.5 accepts one version and
M4 implements the other, the two will diverge.

**Consequence:** Type divergence is a guaranteed maintenance defect. M4 must
de-duplicate before any correlation work proceeds.

---

### BF-5 — CI smoke-test path defect masks build regressions (MAJOR)

**Source:** `.github/workflows/ci.yml` cross-compiles to `/tmp/nulq-amd64` but the
smoke-test step runs `./bin/nulq` (nonexistent). Identified in
`M4-ENGINEERING-BLUEPRINT.md:73-74` and `m4-capability-inventory.md:443-444`.

**Explanation:** CI cannot verify that the built binary actually runs. M4 validation
depends on CI passing (`m4-validation-strategy.md:32-33`), but CI's smoke test is
broken. This means M4 code changes could pass CI while the binary is non-functional.

**Consequence:** M4 cannot trust CI as a validation gate. Local cross-compile and
manual smoke testing are required, but this is not documented as an M4 prerequisite.

---

## Architecture challenge findings

### AR-1 — Entity model solves a real gap but pipeline ordering is misleading (MODERATE)

**Source:** `m4-architecture.md:54-58` places Entity Normalization before Detection
Rules in the target pipeline diagram. `m4-capability-inventory.md:215-228` confirms
no `Entity` type exists and relationships use ad-hoc IDs, often empty.

**Challenge:** The pipeline diagram shows:
```
Entity Normalization → Relationship Graph → Detection Rules → Correlation Engine
```
But M4.3 rules do not depend on entities or relationships
(`m4-implementation-plan.md:17` — M4.3 depends on "none"). If rules don't consume
entities, placing entity normalization before rules in the pipeline implies a data
flow that doesn't exist. Entities are only consumed by correlation (M4.2), which is
blocked on M3.5.

**Consequence:** The architecture diagram suggests a dependency (rules → entities)
that is not implemented. This misleads implementers about what M4.1 actually enables.

---

### AR-2 — Correlated findings use `COR-<NNN>` as `RuleID`, breaking the finding model contract (MAJOR)

**Source:** `m4-data-model.md:284-286` and `m4-technical-decision-records.md:D2`.
`finding.go:42` sets `RuleID: meta.ID` from `RuleMetadata`. `executor.go:342`
validates `finding.RuleID != meta.ID` for rule output.

**Challenge:** `executor.validateRuleOutput` enforces that a finding's `RuleID`
matches the rule that produced it. Correlated findings with `RuleID = "COR-001"`
would fail this validation because no registered rule has ID `COR-001`. The
blueprint documents this as a "documented exception" (`m4-technical-decision-records.md:D2`)
but provides no code change to `validateRuleOutput` to accommodate it.

**Consequence:** Correlation findings cannot pass through the existing executor
validation without modifying `validateRuleOutput`. This is an unimplemented interface
change that M4.2 depends on.

---

### AR-3 — Aggregation has no support for merging correlation findings (MAJOR)

**Source:** `internal/engine/aggregation/aggregation.go` merges findings from rules
only. `m4-implementation-plan.md:74-76` says aggregation "merges rule + correlation
findings, dedups by stable ID, re-validates referential integrity."

**Challenge:** `aggregation.Merge` validates each finding's evidence against the
evidence set returned by the same rule (`executor.go:348-352`). Correlation findings
cite evidence from multiple rules/observations. The current aggregation has no
concept of cross-rule evidence provenance. M4.2 requires modifying `aggregation.Merge`
to accept correlation findings and validate their evidence against a global evidence
set, not per-rule.

**Consequence:** M4.2's core deliverable (aggregation merge) has no defined interface
in the current code. The design assumes a function signature and validation behavior
that does not exist.

---

### AR-4 — `internal/detection/policy` package is entirely unimplemented with no interface design (MODERATE)

**Source:** `m4-implementation-plan.md:149-171` proposes `internal/detection/policy`
but the package does not exist in the source tree. No interface, no file format
decision (YAML vs JSON is "decided at implementation"), no CLI flag design.

**Challenge:** M4.5 is listed as independent of M3.5 and ready to implement, but there
is zero design beyond "policy file selects rules and overrides severity." The
blueprint does not specify:
- How policy interacts with `ruleSet.Select()` in `app.go:62-65`
- Whether policy can override severity below the rule's default (security risk)
- How policy overrides are reflected in the report (contradicts "severity overrides recorded in report" in `m4-candidate-workstreams.md:331`)

**Consequence:** M4.5 is not implementation-ready. It requires interface design before
any code can be written.

---

### AR-5 — Mount context extension (M4.4) has no defined observation attribute changes (MODERATE)

**Source:** `m4-architecture.md:86` lists `internal/platform/linux/filesystem/mounts.go`
extension. `m4-technical-decision-records.md:D6` says mount context is "additive
attributes" on existing `filesystem.file`/`filesystem.directory` observations.

**Challenge:** The blueprint does not specify which attribute keys are added, how
bind source is recorded, or how propagation is interpreted. `attributes.go` already
defines `AttrMountSource`, `AttrSuperOptions`, `AttrMountOptional` — but no rule
reads them. The M4.4 design does not specify how `ResolveMount` is extended to return
bind-source chains, nor how a bind-mounted executable's effective mount differs from
its namespace-visible mount.

**Consequence:** M4.4's mount-context work is underspecified. The attribute contract
between collector and rule is undefined.

---

### AR-6 — Deterministic serialization normalizes `DetectedAt` to zero time, producing invalid-looking timestamps (MODERATE)

**Source:** `m4-technical-decision-records.md:D3` and the implemented
`normalizeDeterministic` in `internal/app/app.go` (set `report.Findings[i].DetectedAt = ref.UTC()`
where `ref` is `time.Time{}`).

**Challenge:** `time.Time{}` marshals as `"0001-01-01T00:00:00Z"` in JSON. This is
a valid RFC3339 timestamp but semantically meaningless — it suggests the finding was
detected at year 1. Consumers cannot distinguish "deterministic mode" from "corrupted
timestamp." The report ID derived from hostname + zero time means two scans of the
same host produce the same `ReportID` regardless of findings, weakening the report ID
as a unique identifier.

**Consequence:** The deterministic mode design is technically functional but produces
misleading output. A better approach would be to omit `DetectedAt` entirely in
deterministic mode (schema allows `omitempty`? No — `DetectedAt` has no `omitempty`
in `finding.go:33`) or use a well-known placeholder.

---

### AR-7 — NULQ-SYS-006 duplicates NULQ-SYS-001 (MODERATE)

**Source:** `m4-detection-specification.md:203-208` acknowledges NULQ-SYS-006 checks
`kernel.unprivileged_userns_clone`, the same parameter as NULQ-SYS-001 in the
sysctl baseline (`sysctl.go:115-119`).

**Challenge:** The blueprint calls them "complementary not duplicative" but both rules
fire on the same observation with the same condition (`value != 0`). NULQ-SYS-001
already reports this at INFO severity. NULQ-SYS-006 adds no new information — it
duplicates an existing finding. Aggregation dedups by `Finding.ID` (rule ID +
resource + title), so both findings would appear separately with different IDs,
creating duplicate noise.

**Consequence:** NULQ-SYS-006 provides no incremental security value over
NULQ-SYS-001. It should be removed or merged into NULQ-SYS-001.

---

### AR-8 — NULQ-SYS-003 declares `Required` kinds it does not use (MINOR)

**Source:** `m4-detection-specification.md:48-49` declares Required:
`process.info`, `identity.execution_context`. The implemented rule
`internal/rules/system/capabilities.go` reads only `models.KindProcess`.

**Challenge:** The rule's metadata declares `identity.execution_context` as required,
but the rule never reads execution context observations. `needsProcess()` in
`app.go:262-270` would trigger process collection, but `needsSystemd()` etc. would
not trigger execution context collection because no rule requires it... actually
`identity.execution_context` is required by NULQ-SYS-003, so the identity collector
would run. But the rule doesn't use those observations. This is a declaration
mismatch.

**Consequence:** The `Required` declaration is inaccurate. The engine skips rules
when required kinds are missing (`executor.go:274-279`), so a system without
execution context observations would skip NULQ-SYS-003 even though it could run on
process observations alone.

---

### AR-9 — NULQ-SYS-004 seccomp rule is too narrow to be useful (MODERATE)

**Source:** `m4-detection-specification.md:103-144` and implemented
`internal/rules/system/seccomp.go`.

**Challenge:** The rule only fires when `euid == 0` AND `seccomp == 0` (disabled).
Most processes are not root. Most root processes on modern systems have seccomp
filtering. The finding is so narrowly scoped that it will almost never fire. Worse,
the rule reports `seccomp` as a string attribute but `/proc/<pid>/status` Seccomp
field values are 0/1/2 — the rule correctly handles this but provides no value for
seccomp=1 (filter) or seccomp=2 (strict), which are the common cases.

**Consequence:** The rule's security value is minimal. It detects a rare
configuration (root + seccomp disabled) and reports it at INFO. The effort to
implement and maintain it exceeds its detection value.

---

### AR-10 — NULQ-SYS-005 systemd rule reads host paths that won't exist in lab containers (MODERATE)

**Source:** `m4-detection-specification.md:148-190` and implemented
`internal/platform/linux/systemd/collector.go:28-35` reads
`/etc/systemd/system`, `/run/systemd/system`, `/usr/lib/systemd/system`,
`/lib/systemd/system`.

**Challenge:** The lab environment (Alpine container) does not have systemd or unit
files. The rule requires `KindSystemdUnit` observations, which the systemd collector
will produce zero of in the lab. M4 validation strategy says M4.3 rules are
"lab-testable on fixtures that include a root-run systemd unit" — but the lab
container cannot provide real systemd unit files. Synthetic fixtures via
`ProcRoot`-style overrides would be needed, but the systemd collector has no
`UnitRoots` override... actually it does (`Options.UnitRoots`), but `app.go` calls
`systemd.NewCollector(systemd.Options{}, logger)` with empty options, so no override
is possible from the CLI.

**Consequence:** M4.3's systemd rule cannot be validated in the lab environment
without additional test infrastructure that does not exist.

---

### AR-11 — The synthetic JSON example in m4-data-model.md shows entities/relationships in the report, but the design says they're internal only (MINOR)

**Source:** `m4-data-model.md:329-391` shows `"entities"` and `"relationships"` arrays
in the example JSON. `m4-data-model.md:85-86` and `m4-architecture.md:91` say entities
and relationships are "internal to the engine; NOT emitted in the default report."

**Contradiction:** The example shows them emitted. The text says they're not.
Implementers cannot tell which is correct.

---

### AR-12 — No schema change is described for new fields, but new fields are added (MODERATE)

**Source:** `m4-data-model.md:401-408` claims "No schema version bump is required in M4"
and "no field removal or re-typing." But M4.3 adds new observation kinds
(`KindSystemdUnit`), new attributes (`AttrCapEffective`, `AttrSeccomp`,
`AttrSystemdUser`, etc.), and M4.4 adds deterministic timestamps.

**Challenge:** JSON Schema allows additional properties by default, but
`schemas/nulq-report-v1.schema.json` may use `additionalProperties: false`. The
blueprint does not check the schema. New observation kinds appear in
`Observation.Kind` which may be validated by the schema. If the schema restricts
`Kind` to an enum, adding `KindSystemdUnit` breaks schema validation.

**Consequence:** M4 may produce reports that fail schema validation. The schema
compatibility claim is unverified.

---

## Detection rule challenge findings

### DR-1 — NULQ-SYS-003: Positive scenario analysis

**Positive:** Process with `euid=0`, `CapEff` containing `CAP_DAC_OVERRIDE` (0x4).
→ MEDIUM finding. Correct behavior.

**Negative 1:** Process with `euid=1000`, `CapEff` empty. → No finding. Correct.

**Negative 2:** Process with `euid=0`, `CapEff` containing only `CAP_CHOWN` (not in
privilege-bypassing set). → No finding. Correct.

**Incomplete evidence:** `CapEff` attribute absent (collector didn't read it). → Rule
skips the process. Correct (no assumption).

**Conflicting observation:** Two processes, one with `CapEff=0x4` (root), one with
`CapEff=0x0` (root). → One finding for the capable process. Correct.

**False-positive risk:** `CAP_SYS_ADMIN` is held by many legitimate system processes
(init, container runtimes). Severity MEDIUM for root processes is defensible but
noisy. The rule does not check if the capability is in the bounding set (which may
be smaller than effective).

**False-negative risk:** File capabilities (`security.capability` xattr) on
executables are not read. A non-root executable with file caps that elevate to
`CAP_DAC_OVERRIDE` would not be detected because the rule reads process
`CapEff`, not executable xattr.

**Severity challenge:** MEDIUM for root + capability is reasonable. INFO for
non-root + capability is reasonable. Neither claims exploitability.

**Minimum sufficient evidence:** `process_euid` + `cap_effective` observed.

---

### DR-2 — NULQ-SYS-004: Positive scenario analysis

**Positive:** Process `euid=0`, `Seccomp=0` (disabled). → INFO finding.

**Negative 1:** `euid=0`, `Seccomp=2` (strict). → No finding. Correct.

**Negative 2:** `euid=1000`, `Seccomp=0`. → No finding (unprivileged). Correct.

**Incomplete evidence:** `Seccomp` attribute absent (kernel doesn't expose it or
/proc/<pid>/status unreadable). → Rule skips. Correct.

**Conflicting observation:** N/A — single attribute per process.

**False-positive risk:** Low (only root + disabled). But seccomp disabled is common
for root processes in containers — this may fire frequently in container
environments where it's expected.

**False-negative risk:** High. seccomp=1 (filter) with a weak BPF program is not
detected. seccomp=2 (strict) is fine. The rule only detects the absence of
filtering, not the quality of filtering.

**Severity challenge:** INFO is appropriate — seccomp absence is defence-in-depth,
not a boundary crossing.

**Minimum sufficient evidence:** `process_euid` + `seccomp` mode.

---

### DR-3 — NULQ-SYS-005: Positive scenario analysis

**Positive:** Unit file `User=root` (or unset), no `NoNewPrivileges=yes`. → LOW finding.

**Negative 1:** `User=root`, `NoNewPrivileges=yes`. → No finding. Correct.

**Negative 2:** `User=nobody`, no `NoNewPrivileges`. → No finding (not root-run). Correct.

**Incomplete evidence:** Unit file unreadable. → Skip unit. Correct.

**Conflicting observation:** `User=root` and `NoNewPrivileges=true` (non-standard
value). → The rule checks `yes/true/1`, so `true` passes → no finding. But systemd
only recognizes `yes` for boolean directives. `true` would be treated as absent by
systemd, so the finding should fire. The rule's acceptance of `true` and `1` is
incorrect for systemd semantics.

**False-positive risk:** A unit intentionally lacking hardening for a specific
workload. Severity LOW mitigates this.

**False-negative risk:** Units running as non-root but with `User=` unset (defaults
to root). The rule checks `user == "" || user == "0" || user == "root"` — unset is
caught. Correct.

**Severity challenge:** LOW is appropriate — configuration gap, not demonstrated
exposure.

**Minimum sufficient evidence:** Unit file path + `User=` + `NoNewPrivileges=`.

**Systemd semantics issue:** systemd boolean directives accept `yes`/`no`, `true`/
`false`, `1`/`0` — actually systemd does accept `true`/`false`/`1`/`0` for booleans.
So the rule's acceptance of these is correct.

---

### DR-4 — NULQ-SYS-006: Positive scenario analysis

**Positive:** `kernel.unprivileged_userns_clone=1`. → INFO finding.

**Negative 1:** `=0`. → No finding. Correct.

**Negative 2:** Sysctl absent from kernel. → No finding. Correct.

**Incomplete evidence:** Value unreadable. → Skip. Correct.

**False-positive risk:** Low — direct kernel parameter observation.

**False-negative risk:** None — the parameter either allows or doesn't.

**Severity challenge:** INFO is appropriate. HIGH confidence is justified (direct
observation).

**Critical issue:** This is a DUPLICATE of NULQ-SYS-001, which already checks the
same parameter at INFO severity. Two rules firing on the same sysctl creates
duplicate findings with different IDs.

**Minimum sufficient evidence:** `kernel.unprivileged_userns_clone` value observed.

---

## Implementation feasibility findings

### IF-1 — M4.1/M4.2 are blocked indefinitely on M3.5 (BLOCKER)

M3.5 acceptance does not exist. M4.1 (entity model) and M4.2 (correlation findings)
cannot be implemented. The blueprint correctly identifies this but understates the
severity — without M3.5, 2 of 6 M4 stages are unimplementable.

### IF-2 — M4.5 (detection policy) has zero interface design (MAJOR)

The package doesn't exist. No file format, no CLI integration, no severity override
semantics. Not implementation-ready.

### IF-3 — M4.4 mount-context extension has no attribute contract (MODERATE)

No attribute keys specified, no `ResolveMount` extension design, no rule that
consumes the new attributes.

### IF-4 — M4.3 rules are implementable now but two have issues (MODERATE)

NULQ-SYS-003, NULQ-SYS-004, NULQ-SYS-005 can be implemented. NULQ-SYS-006 should be
removed (duplicate of NULQ-SYS-001). NULQ-SYS-003's `Required` declaration is
inaccurate.

### IF-5 — Deterministic serialization is implementable but produces year-1 timestamps (MODERATE)

`time.Time{}` marshals as `"0001-01-01T00:00:00Z"`. Should omit `DetectedAt` or use
a sentinel.

---

## Design consistency audit

### CA-1 — Architecture vs data model: entities internal vs example shows them emitted (MINOR)

As noted in AR-11. The data model section 7 shows entities/relationships in JSON
output, but the architecture says they're internal only.

### CA-2 — Data model vs detection spec: NULQ-SYS-003 Required kinds mismatch (MINOR)

As noted in AR-8. Declared Required includes `identity.execution_context` but the
rule only reads `process.info`.

### CA-3 — Detection spec vs validation strategy: systemd rule lab-testability (MODERATE)

Validation strategy claims M4.3 rules are lab-testable with systemd unit fixtures,
but the lab container has no systemd. Requires synthetic fixture infrastructure
that doesn't exist.

### CA-4 — Validation strategy vs acceptance criteria: no acceptance criteria defined
The blueprint documents list test scenarios but no explicit M4 acceptance criteria
(pass/fail thresholds, exit code expectations, schema validation requirements).

### CA-5 — Implementation plan vs package structure: aggregation.Merge unchanged
M4.2 says aggregation merges correlation findings, but `aggregation.Merge` has no
parameter or logic for correlation findings. No interface change specified.

### CA-6 — Risk register vs actual changes: R5 understated
R5 says "New rules label inventory as vulnerability" with mitigations. But
NULQ-SYS-006 duplicates NULQ-SYS-001 (duplicate finding, not just inventory-as-vuln).
This is a different risk not captured.

### CA-7 — Technical decision records vs final recommendation: D2 exception unimplemented
D2 says COR findings use `COR-<NNN>` as RuleID, a "documented exception." But
`executor.validateRuleOutput` would reject this. No code change specified to
accommodate the exception.

---

## Summary of findings by classification

| ID | Classification | Title |
|----|---------------|-------|
| BF-1 | BLOCKER | M3.5 acceptance completely absent |
| BF-3 | BLOCKER | Correlation engine untracked, untested, not in CI |
| IF-1 | BLOCKER | M4.1/M4.2 blocked indefinitely on M3.5 |
| BF-2 | MAJOR | Working tree contains uncommitted M4 implementation code |
| BF-4 | MAJOR | `EvaluationOutcome` duplicated between committed and untracked code |
| BF-5 | MAJOR | CI smoke-test path defect masks build regressions |
| AR-2 | MAJOR | Correlated findings use `COR-<NNN>` as `RuleID`, breaking validation |
| AR-3 | MAJOR | Aggregation has no support for merging correlation findings |
| AR-4 | MAJOR | `internal/detection/policy` entirely unimplemented with no interface design |
| IF-2 | MAJOR | M4.5 has zero interface design |
| AR-1 | MODERATE | Pipeline ordering misleading (entities before rules but rules don't use them) |
| AR-5 | MODERATE | Mount context extension has no attribute contract |
| AR-6 | MODERATE | Deterministic serialization produces year-1 timestamps |
| AR-7 | MODERATE | NULQ-SYS-006 duplicates NULQ-SYS-001 |
| AR-9 | MODERATE | NULQ-SYS-004 too narrow to be useful |
| AR-10 | MODERATE | NULQ-SYS-005 systemd rule can't be validated in lab |
| AR-12 | MODERATE | Schema compatibility for new fields unverified |
| CA-3 | MODERATE | Systemd rule lab-testability claim unverified |
| CA-7 | MODERATE | D2 exception unimplemented in executor validation |
| AR-8 | MINOR | NULQ-SYS-003 Required kinds mismatch |
| AR-11 | MINOR | Synthetic JSON example contradicts internal-only design |
| CA-1 | MINOR | Architecture vs data model inconsistency |
