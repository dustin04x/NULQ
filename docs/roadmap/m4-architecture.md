# M4 Architecture

**NULQ — M4 architecture & engineering blueprint**

This document describes the recommended M4 architecture, showing exactly where M4
changes or extends the existing pipeline, and what remains unchanged.

**Gate note:** M3.5 was not completed. Stages that depend on the relationship model,
evidence integrity, or correlation engine are blocked on M3.5 acceptance and are marked
accordingly.

## Current pipeline (baseline)

```
Linux Environment
   │
   ▼
Discovery Collectors  (filesystem, identity, process, system, acl)
   │
   ▼
Normalized Observations  (closed vocabulary of kinds, content-derived IDs)
   │
   ▼
Immutable Observation Store  (shared by all rules, deduplicated, ordered)
   │
   ▼
Detection Rules  (8 registered rules, precise Required prerequisites)
   │
   ▼
Evidence Evaluation  (every finding cites observation + field)
   │
   ▼
Aggregation  (referential integrity, dedup, deterministic ordering)
   │
   ▼
Report Model  (JSON, JSONL, Markdown, terminal; schema v1.1)
```

## M4 target pipeline

```
Linux Environment
   │
   ▼
Discovery Collectors  (unchanged; + mount-context/bind source attrs in M4.4)
   │
   ▼
Normalized Observations  (unchanged)
   │
   ▼
Immutable Observation Store  (unchanged)
   │
   ▼
Entity Normalization  [M4.1 — blocked on M3.5]   observations → stable entities
   │
   ▼
Relationship Graph  [M4.1 — blocked on M3.5]     validated, deduped, bounded edges
   │
   ▼
Detection Rules  (unchanged; + new hardening rules in M4.3)
   │
   ▼
Correlation Engine  [M4.2 — blocked on M3.5]      relationships + correlated findings
   │
   ▼
Evidence Evaluation  (unchanged; + cross-rule evidence refs)
   │
   ▼
Aggregation  (unchanged; + correlation findings merged)
   │
   ▼
Deterministic Serialization  [M4.4]               stable report bytes
   │
   ▼
Report Model  (unchanged schema; + normalized timestamps)
```

## Components changed or added by M4

| Component | Change | Stage | M3.5 blocked? |
|---|---|---|---|
| `internal/core/entity` | NEW — Entity, EntityID, entity registry | M4.1 | Yes |
| `internal/core/relationship` | NEW — Relationship, RelationshipGraph | M4.1 | Yes |
| `internal/engine/correlation` | EXTEND — emit correlated findings (accepted only after M3.5) | M4.2 | Yes |
| `internal/engine/aggregation` | EXTEND — merge correlation findings, preserve referential integrity | M4.2 | Yes |
| `internal/platform/linux/filesystem/mounts.go` | EXTEND — bind source, propagation, effective mount context | M4.4 | No |
| `internal/app/app.go` | EXTEND — deterministic-report mode, normalized timestamps | M4.4 | No |
| `internal/cli` | EXTEND — `--deterministic` flag | M4.4 | No |
| `internal/detection/policy` | NEW — detection-policy config, rule selection + severity override | M4.5 | No |
| `internal/rules/*` | ADD — new hardening rules (capabilities, seccomp, systemd) | M4.3 | No |
| `internal/core/models` | UNCHANGED (observation/finding/report contracts) | — | — |
| `internal/evidence` | UNCHANGED (builder) | — | — |
| `internal/reporting` | UNCHANGED (renderers, sanitizers) | — | — |
| `schemas/nulq-report-v1.schema.json` | UNCHANGED in M4 (no field removal/re-typing) | — | — |

## Package boundary rules for M4

1. **Collectors never read the filesystem beyond their assigned scope, never spawn
   processes, never print.** Collectors publish observations only.
2. **Rules never read the filesystem, spawn processes, or print.** Rules consume the
   observation store (and, after M4.1, the entity/relationship graph) only.
3. **The engine owns orchestration, cancellation, panic isolation, and per-component
   error isolation.** No component aborts the whole assessment.
4. **New packages are small and single-responsibility.** `entity` owns identity; `relationship`
   owns graph semantics; `correlation` owns cross-rule synthesis; `policy` owns operator
   configuration. No package does two of these.
5. **No abstraction without a concrete justification.** The entity and relationship
   packages exist because the current code has no validated relationship model — a real
   correctness gap, not an aesthetic concern.
6. **No database, external service, network dependency, or third-party runtime.** M4
   remains standard-library-only, read-only, single-process.

## Data flow through M4 stages

### M4.0 — Foundations (prerequisite: M3.5 acceptance)
No code change. Establish that M3.5 relationship model and evidence integrity are
accepted. If M3.5 is not accepted, M4 implementation is paused on the blocked stages.

### M4.1 — Entity normalization + relationship graph (blocked on M3.5)
Observations → entities (stable content-derived IDs) → validated relationship graph.
New packages `internal/core/entity` and `internal/core/relationship`. Rules receive
the observation store unchanged; correlation receives the graph.

### M4.2 — Correlation findings + aggregation (blocked on M3.5)
Correlation engine emits `models.Finding` (not just relationships) with aggregated
severity/confidence and evidence. Aggregation merges rule + correlation findings,
dedups by stable ID, validates referential integrity.

### M4.3 — New detection rules (independent of M3.5)
New rules for capabilities, seccomp, systemd unit security. All LOW/INFO, conservative,
with explicit limitations. Registered explicitly in `internal/rules/rules.go`.

### M4.4 — Deterministic serialization + mount context (mount context independent)
Deterministic-report mode normalizes timestamps and report ID so identical input →
byte-identical JSON. Mount-context extension records bind source / propagation /
effective flags per path.

### M4.5 — Detection policy (independent of M3.5)
Operator policy file selects rules and overrides severity; validated at startup; no code
execution from policy.

## What remains unchanged

- The observation model (kinds, attributes, status, `ObservationID`).
- The finding model (ID = rule + resource + title; `DetectedAt` excluded from ID).
- The evidence builder (`EvidenceID` = observation + field).
- The 8 existing rules and their conservative severity semantics.
- The JSON schema (v1.1) — no fields removed or re-typed.
- Read-only, std-library-only, no-network, no-privilege restrictions.
- CLI exit-code contract (0/1/2/3).
- `go vet`/`go test`/`-race`/amd64+arm64 cross-compile verification.

## Error handling in M4

All new components wrap failures in `internal/core/errors` classes
(`permission_denied`, `not_found`, `unavailable`, `unsupported`, `malformed_input`,
`timeout`, `canceled`, `resource_exhausted`, `internal`). Unavailability is data — a
relationship that cannot be validated is reported as invalid/unknown, never silently
dropped as valid.

## Test strategy per component

| Component | Unit | Integration | Adversarial | Property | Fuzz | Race |
|---|---|---|---|---|---|---|
| entity | ✓ | | ✓ | ✓ (ID stability) | | |
| relationship | ✓ | | ✓ (cycles, dedup) | ✓ (deterministic graph) | | |
| correlation | ✓ | ✓ | ✓ (severity/confidence boundaries) | | | |
| aggregation | ✓ | | ✓ (dangling refs) | ✓ (dedup consistency) | | |
| mounts (bind context) | ✓ | | ✓ (escaped fields) | | ✓ (mountinfo parse) | |
| deterministic serialization | | ✓ (two scans identical) | | ✓ (byte-identical) | | |
| policy | ✓ | | ✓ (invalid IDs) | | | |

## Rollback considerations

Each stage is independently reviewable and can be reverted without affecting later
stages because new packages are additive and existing contracts are unchanged. M4.1 and
M4.2 are the only stages that modify core flow; both are gated behind M3.5 acceptance
so they can be deferred without blocking M4.3/M4.4/M4.5.

## Architectural risks

1. **M3.5 unverified foundation.** M4.1/M4.2 assume the correlation engine and evidence
   integrity are sound. If M3.5 rejects them, M4.1/M4.2 must be redesigned.
2. **Entity ID stability vs. observation evolution.** If observation attributes change,
   entity IDs derived from them may change; entity IDs must be documented as
   observation-content-dependent, not system-state-stable across attribute schema
   changes.
3. **Correlation false positives.** Aggregated findings must never promote severity on
   low confidence; this must be tested at the severity boundary.
4. **Deterministic serialization scope.** Wall-clock fields that must remain dynamic
   (report start/finish) must be clearly excluded from the determinism guarantee.
