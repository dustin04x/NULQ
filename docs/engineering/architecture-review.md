# Architecture Review — NULQ

This review evaluates NULQ's architecture against its stated design
principles and the mission invariants. It covers the component boundaries,
data flow, and architectural decisions as of commit f63aeba.

## 1. Component boundaries

```
cmd/nulq                    entry point (signal handling + exit code only)
internal/app                 wiring: collectors + selected rules + report
internal/cli                 flags, output routing, exit codes
internal/core/models         observation/evidence/finding/report contracts
internal/core/errors         typed error classes
internal/core/interfaces     Collector, Rule, ObservationSet contracts
internal/engine/*            registry, store, executor, aggregation, correlation
internal/platform/linux/*    collectors (system, identity, filesystem, process, systemd, acl)
internal/rules/*             detection modules grouped by domain
internal/evidence            evidence builder
internal/reporting           renderers and sanitizers
internal/lab                 lab manifest, schema validator, verdict engine
pkg/api                      public report types for external consumers
schemas/                     published JSON Schema
```

**Boundary integrity**: Collectors never assign severity. Rules never read the
filesystem, spawn processes, or print. Renderers never collect. This
separation is enforced by interface types and observed in the code.

## 2. Data flow

1. CLI parses flags and validates rule/module selection (rejects before scan)
2. `app.Scan` builds collector list based on selected rules' required kinds
3. Executor runs collectors concurrently with bounded semaphore, timeouts, panic isolation
4. Observations are stored in `store.Memory` (deduplicated by ID)
5. Executor runs rules concurrently; each rule receives an `ObservationSet`
6. Rules that lack required kinds are skipped with a reason
7. Rule failures/panics are isolated; other rules continue
8. Aggregation merges findings+evidence, validates referential integrity,
   removes duplicates, produces deterministic ordering
9. Correlation engine runs on observations (produces relationships, not findings)
10. `buildReport` assembles the Report with coverage, stats, limitations
11. `--deterministic` normalizes all timestamps
12. Renderer (JSON/JSONL/Markdown/Terminal) emits the report

## 3. Adherence to mission invariants

| Invariant | Status | Evidence |
|-----------|--------|----------|
| Read-only | Pass | No write syscalls in collectors; no service management; no binary execution |
| Evidence-backed findings | Pass | `Finding.Validate()` requires non-empty evidence; aggregation rejects dangling references |
| Deterministic IDs and ordering | Pass | SHA-256 content-derived IDs; `SortFindings` deterministic |
| No fabricated results | Pass | All findings derive from collected observations |
| No silent failures | Pass | Unavailable data published as observations with status and error class |
| Standard library only | Pass | `go.mod` has no dependencies |
| Machine output sterile | Pass | JSON/JSONL on stdout; logs on stderr only |
| Sanitize untrusted text | Pass | `reporting/sanitize.go` strips control characters |
| Coverage honesty | Pass | `execution_complete` and `coverage_complete` are separate fields |

## 4. Architectural strengths

1. **Explicit registration**: Rules are registered explicitly in
   `internal/rules/rules.go`, not discovered. The binary contains exactly
   the rules its documentation describes.
2. **Failure isolation**: Panic recovery, timeouts, and context cancellation
   at both collector and rule level. One failing component never aborts the
   scan.
3. **Referential integrity**: Aggregation validates that every cited evidence
   ID exists. The lab validator audits for duplicates, dangling references,
   and findings without evidence.
4. **Coverage honesty**: Separation of `execution_complete` (did everything
   run?) from `coverage_complete` (was everything observed?) prevents
   overstating assessment completeness.
5. **Deterministic output**: Stable IDs, deterministic ordering, and
   `--deterministic` timestamp normalization enable byte-identical reports
   for identical input.

## 5. Architectural concerns

### 5.1 Correlation engine is finding-adjacent but not finding-generating

The correlation engine (`internal/engine/correlation/engine.go`) runs on
every scan and produces `CorrelationResult` with relationships. Per M10,
correlation is explicitly labelled as design and must not generate findings.
This is correctly implemented but creates a conceptual boundary that future
work (M5 correlation) will need to navigate carefully.

### 5.2 No dedicated store test

`internal/engine/store` has no test file. The store is used by the executor
and all rule tests but is not directly tested.

### 5.3 No systemd collector test

`internal/platform/linux/systemd` has no test file. The collector was added
in M4 without dedicated test coverage.

### 5.4 Evidence builder has no test

`internal/evidence` has no test file despite being central to the
evidence-backed findings invariant.

### 5.5 CI smoke-test path (fixed)

The CI workflow compiled the binary to `/tmp/nulq-amd64` but the smoke test
invoked `./bin/nulq`. Fixed in this takeover. A secondary issue — the
fail-on test scans an empty directory — was also fixed by adding fixture
creation.

## 6. Boundary risks

| Risk | Mitigation | Residual |
|------|-----------|----------|
| Collector reads host filesystem | Read-only access, exclusion of /proc, /sys, container storage | Unreadable paths reported as unavailable |
| Rule receives mutable observation set | `ObservationSet` interface is read-only; store is immutable after collection | None |
| Terminal escape injection | `sanitize.go` strips control characters before rendering | None |
| Non-deterministic output | `--deterministic` normalizes all timestamps including evidence | Live process PIDs differ between runs (expected) |

## 7. Recommendations

1. Add dedicated tests for `internal/engine/store`, `internal/evidence`,
   and `internal/platform/linux/systemd`.
2. Add benchmark tests for collectors and rules.
3. Add fuzzing for mountinfo parser and ACL parser.
4. Create lab manifest files and Docker laboratory.
5. Document the correlation/finding boundary more explicitly in code comments.
