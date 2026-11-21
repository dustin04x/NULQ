# M4 Engineering Blueprint

**NULQ — Find the boundary. Understand the exposure.**

This document is the entry point for the M4 milestone design. It links to all supporting
specification documents and records the M3.5 readiness gate that governs whether M4
implementation may proceed.

## M3.5 readiness assessment (gate)

**M3.5 was not completed.** No M3.5 acceptance documents exist in this repository:

| Expected document | Status |
|---|---|
| `docs/audits/m35-baseline.md` | absent |
| `docs/audits/m35-architecture-review.md` | absent |
| `docs/audits/m35-adversarial-scenarios.md` | absent |
| `docs/audits/m35-evidence-integrity.md` | absent |
| `docs/audits/m35-linux-semantics-review.md` | absent |
| `docs/audits/m35-fuzzing-report.md` | absent |
| `docs/audits/m35-reliability-review.md` | absent |
| `docs/audits/m35-performance-report.md` | absent |
| `docs/audits/m35-remediation-register.md` | absent |
| `docs/audits/m35-final-engineering-report.md` | absent |

Consequently there is **no M3.5 final verdict** (ACCEPTED / CONDITIONALLY ACCEPTED /
REJECTED) and no verified M3.5 remediation register.

Per the M4 mandatory gate: because M3.5 reports are missing/incomplete/unverified, this
fact is stated explicitly here, and M4 design must **not** treat the existing foundation
as reliable. In particular:

- The correlation engine (`internal/engine/correlation/`) is uncommitted, untracked,
  in-progress work. It is not part of any accepted milestone and is not covered by
  tests or CI.
- The uncommitted changes to `internal/core/models/severity.go` (adds `EvaluationOutcome`)
  and `internal/engine/executor/executor.go` (wires the correlation engine into the scan)
  are likewise in-progress and unaccepted.
- M2 is documented as "implementation complete — conditionally accepted" in `README.md`,
  with outstanding verification conditions (Docker/Alpine lab E2E, HIGH-severity live
  fixture, lab scenario refresh) that remain blocked.

M4 planning below proceeds **with caveats**, explicitly marking which design decisions
depend on unverified M3.5 foundations and which require M3.5 to reach acceptance first.

## Supporting documents

| Document | Purpose |
|---|---|
| `docs/roadmap/m4-capability-inventory.md` | Capability and gap inventory for every subsystem |
| `docs/roadmap/m4-technical-landscape.md` | Comparative security-engineering landscape analysis |
| `docs/roadmap/m4-candidate-workstreams.md` | Candidate M4 workstreams, ranked |
| `docs/roadmap/m4-architecture.md` | Recommended M4 architecture |
| `docs/roadmap/m4-data-model.md` | Proposed M4 data model (observations, entities, relationships, evidence, findings) |
| `docs/roadmap/m4-detection-specification.md` | Proposed M4 detection rules and semantics |
| `docs/roadmap/m4-validation-strategy.md` | M4 testing and validation plan (15+ scenarios) |
| `docs/roadmap/m4-implementation-plan.md` | Phased implementation stages (M4.0–M4.5) |
| `docs/roadmap/m4-risk-register.md` | Security, reliability, and scope risks |
| `docs/roadmap/m4-technical-decision-records.md` | Architecture decision records for M4 |

## Repository state at the time of this blueprint

- Branch: `master` (tracks `origin/master`)
- Starting commit: `0ad68b5` ("trigger pipeline after binary fix")
- Working tree: **not clean** — contains uncommitted in-progress correlation-engine work
  (`internal/core/models/severity.go`, `internal/engine/executor/executor.go`) and untracked
  files (`internal/engine/correlation/`, `tests/integration/correlation_test.go`).
- No commits or pushes were made as part of this blueprint task. Production code was not
  modified.
- `go.mod`: module `github.com/dustin04x/nulq`, Go 1.24.0, standard library only
  (no `go.sum`, no external dependencies).
- Build/vet/test/race: all pass.
- CI defect confirmed: `.github/workflows/ci.yml` cross-compiles to
  `/tmp/nulq-amd64` but the smoke-test step runs `./bin/nulq`, which does not exist.

## How to read this blueprint

Each supporting document is implementation-ready: it names real packages, file paths,
rule IDs, and observation kinds drawn from the actual source. No proposed M4 capability
is claimed to already exist. Nothing here modifies Go source, tests, schemas, CLI
behavior, dependencies, or CI.

## Final recommendation

Whether this blueprint is ready for engineering implementation depends on first resolving
the M3.5 gate. See `m4-implementation-plan.md` for the explicit dependency and
`m4-risk-register.md` for the risks of proceeding on an unverified foundation.
