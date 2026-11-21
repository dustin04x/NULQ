# M4 Implementation Plan

**NULQ — M4 architecture & engineering blueprint**

This document sequences M4 work into reviewable stages, lists dependencies, entry/exit
criteria, and rollback points. It does not implement any M4 code.

**Gate note:** M3.5 was not completed. Stages M4.1 and M4.2 are blocked on M3.5 acceptance.

## Stage summary

| Stage | Name | Depends on | M3.5 blocked? | Deliverable |
|---|---|---|---|---|
| M4.0 | Foundations gate | M3.5 acceptance | Yes (gate) | Go/no-go decision |
| M4.1 | Entity normalization + relationship graph | M3.5 | Yes | `internal/core/entity`, `internal/core/relationship` |
| M4.2 | Correlation findings + aggregation | M4.1 | Yes | `internal/engine/correlation` extension, aggregation merge |
| M4.3 | New detection rules | none | No | `internal/rules/*` new rules |
| M4.4 | Deterministic serialization + mount context | none | No | `internal/app`, `internal/cli`, mounts extension |
| M4.5 | Detection policy | none | No | `internal/detection/policy` |

## Stage M4.0 — Foundations gate

**Purpose:** Establish whether M3.5 relationship model and evidence integrity are accepted
before any M4 code touches core flow.

**Entry criteria:**
- M3.5 acceptance decision documented (accepted / rejected / deferred).
- If rejected: M4.1/M4.2 deferred; M4.3/M4.4/M4.5 proceed independently.

**Exit criteria:**
- Go/no-go decision recorded in `CHANGELOG.md`.
- If go: proceed to M4.1. If no-go: M4.1/M4.2 blocked; M4.3/M4.4/M4.5 active.

**Rollback:** None (decision-only).

---

## Stage M4.1 — Entity normalization + relationship graph

**Purpose:** Introduce stable entity identities and a validated relationship graph as
internal (non-emitted) infrastructure for correlation.

**Entry criteria:** M4.0 go.

**Exit criteria:**
- `internal/core/entity` package: `Entity`, `EntityID`, registry, ID stability, provenance.
- `internal/core/relationship` package: `Relationship`, `RelationshipType`, `RelationshipGraph`,
  validation, dedup, cycle detection, deterministic edge order.
- Unit tests pass (positive, negative, unavailable).
- Adversarial tests pass (hostile fields, dangling refs, cycles).
- `go vet ./...`, `go test ./...`, `go test -race ./...` pass.
- Cross-compile amd64 + arm64 passes.
- No existing package modified (additive only).

**Implementation notes:**
- New packages only; no modification to `internal/core/models`, `internal/evidence`,
  `internal/rules`, `internal/reporting`.
- Entities and relationships are NOT emitted in the default report (M4.4 decision).
- Graph construction is single-threaded per scan; concurrent access not supported.

**Rollback:** Revert `internal/core/entity` and `internal/core/relationship` packages;
tests and CI unchanged.

---

## Stage M4.2 — Correlation findings + aggregation

**Purpose:** Correlation engine emits `models.Finding`; aggregation merges rule + correlation
findings with referential integrity.

**Entry criteria:** M4.1 complete and accepted.

**Exit criteria:**
- `internal/engine/correlation` emits `models.Finding` with scenario `RuleID`.
- Aggregation merges rule findings + correlation findings, dedups by stable ID.
- Aggregation validates referential integrity (no dangling evidence references).
- Severity cap: low-confidence constituents never raise severity; HIGH requires
  `EvaluationConfirmed`.
- Confidence: weakest-link min preserved.
- Unit + integration tests pass (positive, negative, unavailable, severity boundary).
- `go vet ./...`, `go test ./...`, `go test -race ./...` pass.
- Cross-compile amd64 + arm64 passes.

**Implementation notes:**
- Blocked on M4.1 (entities/relationships).
- Blocked on M3.5 (correlation engine acceptance).
- Correlated findings use `COR-<NNN>` as `RuleID`; this is a documented exception to the
  "RuleID must be a registered detection rule" convention.

**Rollback:** Revert correlation-finding emission and aggregation merge; aggregation
returns to rule-only findings.

---

## Stage M4.3 — New detection rules

**Purpose:** Add conservative hardening rules for capabilities, seccomp, systemd, userns.

**Entry criteria:** none (independent of M3.5).

**Exit criteria:**
- New rules: `NULQ-SYS-003` (capabilities), `NULQ-SYS-004` (seccomp),
  `NULQ-SYS-005` (systemd), `NULQ-SYS-006` (userns).
- All rules registered in `internal/rules/rules.go` `All()`.
- Each rule: positive, negative, unavailable tests including severity boundary.
- Each rule: explanation, impact, remediation, limitations documented.
- `go vet ./...`, `go test ./...`, `go test -race ./...` pass.
- Cross-compile amd64 + arm64 passes.
- Changelog entry per rule.

**Implementation notes:**
- New rules read only (no process execution, no D-Bus).
- Systemd rule reads unit files from filesystem only; no runtime activation state.
- Capabilities rule reads `/proc/<pid>/Status` only; no file capabilities xattr.
- Default severity INFO/LOW/MEDIUM only; no HIGH/CRITICAL for new rules.

**Rollback:** Remove new rule files and registration entries; existing rules unchanged.

---

## Stage M4.4 — Deterministic serialization + mount context

**Purpose:** Deterministic-report mode (byte-identical output for identical input) and
mount-context extension (bind source, propagation, effective flags).

**Entry criteria:** none (independent of M3.5; mount context independent of correlation).

**Exit criteria:**
- `--deterministic` flag in `internal/cli`.
- `internal/app` deterministic-report mode normalizes timestamps/report ID.
- Mount-context extension records bind source, propagation, effective mount flags per path.
- Deterministic mode: two scans of identical fixture → byte-identical JSON.
- Default mode unchanged (wall-clock `DetectedAt` preserved).
- Mount context does not alter existing observation kinds (additive attributes).
- `go vet ./...`, `go test ./...`, `go test -race ./...` pass.
- Cross-compile amd64 + arm64 passes.

**Implementation notes:**
- Determinism excludes `DetectedAt` (normalized to scan start) and any wall-clock
  fields; documented explicitly.
- Mount context read-only; no mount traversal beyond assigned scope.
- Existing schema v1.1 unchanged (no field removal/re-type).

**Rollback:** Revert `--deterministic` flag and mount-context attributes; default
behavior unchanged.

---

## Stage M4.5 — Detection policy

**Purpose:** Operator policy file selects rules and overrides severity; validated at
startup; data-only (no code execution).

**Entry criteria:** none (independent of M3.5).

**Exit criteria:**
- `internal/detection/policy` package: policy load, validation, rule selection,
  severity override.
- Policy rejects invalid rule IDs, invalid severities, path traversal.
- Policy cannot execute code (data-only; no script/eval).
- Unit tests: validation, override, rejection.
- `go vet ./...`, `go test ./...`, `go test -race ./...` pass.
- Cross-compile amd64 + arm64 passes.

**Implementation notes:**
- Policy file format: YAML or JSON (decided at implementation).
- Policy applied at scanner startup before collection.
- No hot-reload; policy fixed for the scan duration.

**Rollback:** Remove `internal/detection/policy` package; CLI flag removed; scanner
runs all rules as before.

---

## Dependency graph

```
M3.5 (gate) ──→ M4.0 ──→ M4.1 ──→ M4.2
                  │
                  ├─→ M4.3
                  ├─→ M4.4
                  └─→ M4.5
```

M4.3, M4.4, M4.5 can proceed in parallel once M4.0 go/no-go is recorded. M4.1 and M4.2
are sequential and both blocked on M3.5.

## Reviewable unit boundaries

Each stage is a separate, reviewable change:
- M4.1: two new packages + tests.
- M4.2: correlation extension + aggregation change + tests.
- M4.3: four new rule files + registration + tests.
- M4.4: CLI flag + app change + mounts extension + tests.
- M4.5: policy package + tests.

No stage combines unrelated formatting churn.

## Rollback policy

- Each stage is independently revertible without affecting later stages.
- M4.1/M4.2 are the only stages modifying core flow; both gated behind M3.5 acceptance
  so they can be deferred without blocking M4.3/M4.4/M4.5.
- Revert removes only the stage's additions; existing code untouched.

## Estimated effort (indicative, not committed)

| Stage | Scope | Effort |
|---|---|---|
| M4.0 | Decision documentation | small |
| M4.1 | 2 new packages, tests | medium |
| M4.2 | Correlation + aggregation, tests | medium-large |
| M4.3 | 4 rules, tests, docs | medium |
| M4.4 | Determinism + mounts, tests | medium |
| M4.5 | Policy package, tests | small-medium |

Total: approximately 6 reviewable PRs across 5 stages.
