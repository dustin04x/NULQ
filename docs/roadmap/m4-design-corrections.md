# M4 Design Corrections

**NULQ — Design corrections addressing findings from m4-red-team-review.md**

Each correction maps to a review finding ID and states the required change, the
affected documents, and whether it blocks M4 acceptance.

---

## Correction DC-1 — Complete M3.5 acceptance before M4.1/M4.2

**Addresses:** BF-1, BF-3, IF-1

**Required change:** M3.5 must be completed, documented, and accepted before any
M4.1 (entity model) or M4.2 (correlation findings) work proceeds. The M4
blueprint's claim that M4.1/M4.2 are "blocked on M3.5" is correct but understated:
without an M3.5 verdict, M4 stages 1 and 2 are unimplementable.

**Affected documents:**
- `docs/roadmap/M4-ENGINEERING-BLUEPRINT.md` — restate M3.5 gate as hard blocker
- `docs/roadmap/m4-implementation-plan.md` — entry criteria for M4.1/M4.2 require
  M3.5 acceptance document

**Blocker status:** Yes — M4.0 cannot issue "go" without M3.5 verdict.

---

## Correction DC-2 — Commit or revert all uncommitted M4 implementation code

**Addresses:** BF-2

**Required change:** Either commit all uncommitted M4 implementation changes as part
of an accepted M4 milestone, or revert them so the working tree matches the
documentation-only blueprint. The current state (uncommitted implementation code
contradicting "documentation-only" claims) makes the blueprint unreliable as a
reference.

**Files to either commit or revert:**
- `internal/core/models/severity.go` — `EvaluationOutcome` type
- `internal/engine/executor/executor.go` — correlation engine wiring
- `internal/engine/correlation/` — engine.go, scenarios/scenarios.go
- `internal/rules/system/capabilities.go` — NULQ-SYS-003
- `internal/rules/system/seccomp.go` — NULQ-SYS-004
- `internal/rules/system/systemd.go` — NULQ-SYS-005
- `internal/rules/system/userns.go` — NULQ-SYS-006
- `internal/platform/linux/systemd/collector.go` — systemd unit collector
- `internal/platform/linux/process/collector.go` — CapEff/CapBnd/Seccomp parsing
- `internal/core/models/attributes.go` — new attribute constants
- `internal/core/models/observation.go` — KindSystemdUnit
- `internal/evidence/evidence.go` — evidence changes
- `internal/rules/rules.go` — 4 new rule registrations
- `internal/app/app.go` — Deterministic field, systemd wiring
- `internal/cli/scan.go` — `--deterministic` flag
- `internal/cli/cli_test.go` — rule count 8→12
- `tests/integration/correlation_test.go` — correlation smoke test
- `nulq` binary (untracked build artifact — delete, do not commit)

**Blocker status:** Yes — working tree state contradicts documentation.

---

## Correction DC-3 — De-duplicate `EvaluationOutcome`

**Addresses:** BF-4

**Required change:** Keep exactly one definition of `EvaluationOutcome`. Remove the
duplicate from either `internal/core/models/severity.go` or
`internal/engine/correlation/engine.go`. The committed version in
`severity.go` should remain; the correlation engine should import it.

**Blocker status:** Yes — type divergence is guaranteed without de-duplication.

---

## Correction DC-4 — Fix CI smoke-test path

**Addresses:** BF-5

**Required change:** In `.github/workflows/ci.yml`, change the smoke-test step to run
`/tmp/nulq-amd64` (the actual cross-compiled binary path) instead of `./bin/nulq`.
Alternatively, copy `/tmp/nulq-amd64` to `./bin/nulq` before the smoke test.

**Blocker status:** Yes — CI cannot validate binary functionality as-is.

---

## Correction DC-5 — Implement correlation finding interface in executor validation

**Addresses:** AR-2, CA-7

**Required change:** Modify `internal/engine/executor/executor.go`'s
`validateRuleOutput` to accept findings whose `RuleID` does not match a registered
rule ID, provided the RuleID matches the `COR-<NNN>` pattern defined in
`m4-technical-decision-records.md:D2`. Add a `isCorrelationRuleID` check before
the `finding.RuleID != meta.ID` rejection.

**Affected code:** `internal/engine/executor/executor.go`

**Blocker status:** Yes — correlation findings cannot pass executor validation.

---

## Correction DC-6 — Extend aggregation.Merge to accept correlation findings

**Addresses:** AR-3, CA-5

**Required change:** Modify `internal/engine/aggregation/aggregation.go`'s `Merge`
function to accept correlation findings alongside rule findings, validate their
evidence against a global evidence set (not per-rule), and dedup by stable finding
ID. Define the interface change before implementation.

**Affected code:** `internal/engine/aggregation/aggregation.go`

**Blocker status:** Yes — M4.2's core deliverable has no defined interface.

---

## Correction DC-7 — Remove NULQ-SYS-006 (duplicate of NULQ-SYS-001)

**Addresses:** AR-7

**Required change:** Remove NULQ-SYS-006 from `m4-detection-specification.md`,
`internal/rules/rules.go`, and `internal/rules/system/userns.go`. NULQ-SYS-001
already checks `kernel.unprivileged_userns_clone` at INFO severity. Two rules
firing on the same sysctl creates duplicate findings.

**Affected documents:**
- `docs/roadmap/m4-detection-specification.md` — remove NULQ-SYS-006 section
- `docs/roadmap/m4-implementation-plan.md` — update rule count from 4 to 3
- `internal/rules/rules.go` — remove registration

**Blocker status:** No — moderation, not blocker.

---

## Correction DC-8 — Fix NULQ-SYS-003 Required declaration

**Addresses:** AR-8

**Required change:** In `m4-detection-specification.md`, change NULQ-SYS-003's
`Required` from `process.info, identity.execution_context` to `process.info` only,
matching the implemented rule in `internal/rules/system/capabilities.go`.

**Blocker status:** No — engine would skip rule unnecessarily without fix.

---

## Correction DC-9 — Fix NULQ-SYS-004 scope or remove

**Addresses:** AR-9

**Required change:** Either remove NULQ-SYS-004 (seccomp disabled detection for root
processes only) or expand it to detect seccomp filter presence across all users,
not just root. The current rule fires only for `euid=0 AND seccomp=0`, which is
rare and of limited security value.

**Blocker status:** No — moderation.

---

## Correction DC-10 — Make NULQ-SYS-005 lab-testable or mark not lab-testable

**Addresses:** AR-10, CA-3

**Required change:** Either add synthetic systemd unit fixture support to
`internal/platform/linux/systemd/collector.go` (via `Options.UnitRoots` override
exposed through CLI) or state in `m4-validation-strategy.md` that NULQ-SYS-005 is
not lab-testable and why.

**Blocker status:** No — moderation.

---

## Correction DC-11 — Fix deterministic serialization timestamp

**Addresses:** AR-6

**Required change:** In deterministic mode, omit `DetectedAt` from findings rather
than setting it to `time.Time{}` (which marshals as `"0001-01-01T00:00:00Z"`).
If `DetectedAt` cannot be omitted due to schema, use a well-known sentinel like
`"1970-01-01T00:00:00Z"` and document it.

**Affected code:** `internal/app/app.go` `normalizeDeterministic`

**Blocker status:** No — moderation.

---

## Correction DC-12 — Resolve entity/relationship emission contradiction

**Addresses:** AR-11, CA-1

**Required change:** In `m4-data-model.md`, either remove the `"entities"` and
`"relationships"` arrays from the example JSON (section 7) to match the
"internal only" claim in sections 5 and 8, or update sections 5/8 to state they
are emitted. The current contradiction makes implementation ambiguous.

**Blocker status:** No — moderation.

---

## Correction DC-13 — Verify schema compatibility for new observation kinds

**Addresses:** AR-12

**Required change:** Check `schemas/nulq-report-v1.schema.json` for `additionalProperties`
and `Kind` enum constraints. If `Kind` is an enum, add `KindSystemdUnit` to it.
Document whether new attribute constants require schema changes.

**Blocker status:** No — moderation.

---

## Correction DC-14 — Add interface design for M4.5 detection policy

**Addresses:** AR-4, IF-2

**Required change:** Before implementing `internal/detection/policy`, define:
- Policy file format (YAML or JSON)
- CLI flag for policy file path
- How policy interacts with `ruleSet.Select()` in `app.go`
- Severity override semantics (can policy lower severity below rule default?)
- How overrides appear in the report

**Blocker status:** Yes — M4.5 is not implementation-ready without this design.

---

## Correction DC-15 — Define mount-context attribute contract

**Addresses:** AR-5

**Required change:** Specify which attribute keys are added to filesystem
observations for mount context (bind source, propagation, superblock options),
how `ResolveMount` is extended to return bind-source chains, and which rule
consumes them.

**Blocker status:** No — moderation.

---

## Correction DC-16 — Define M4 acceptance criteria

**Addresses:** CA-4

**Required change:** Add explicit M4 acceptance criteria to
`m4-implementation-plan.md`: pass/fail thresholds, exit code expectations,
schema validation requirements, test coverage minimums, and lab scenario
expectations. A zero exit code is not sufficient for a pass.

**Blocker status:** No — moderation.

---

## Summary: which corrections are blockers

| Correction | Blocker? | Finding(s) |
|------------|----------|------------|
| DC-1 M3.5 acceptance | YES | BF-1, BF-3, IF-1 |
| DC-2 Commit or revert code | YES | BF-2 |
| DC-3 De-duplicate EvaluationOutcome | YES | BF-4 |
| DC-4 Fix CI smoke-test path | YES | BF-5 |
| DC-5 Executor validation for COR IDs | YES | AR-2, CA-7 |
| DC-6 Aggregation merge for correlation | YES | AR-3, CA-5 |
| DC-7 Remove NULQ-SYS-006 | No | AR-7 |
| DC-8 Fix NULQ-SYS-003 Required | No | AR-8 |
| DC-9 Fix/remove NULQ-SYS-004 | No | AR-9 |
| DC-10 Systemd lab-testability | No | AR-10, CA-3 |
| DC-11 Deterministic timestamp | No | AR-6 |
| DC-12 Entity/relationship emission | No | AR-11, CA-1 |
| DC-13 Schema compatibility | No | AR-12 |
| DC-14 M4.5 policy interface design | Yes | AR-4, IF-2 |
| DC-15 Mount-context attribute contract | No | AR-5 |
| DC-16 M4 acceptance criteria | No | CA-4 |

**6 blockers, 10 non-blockers.**
