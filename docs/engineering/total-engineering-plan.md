# Total Engineering Plan — NULQ

This document defines the complete remediation, verification, and acceptance
plan for the NULQ total engineering takeover. It is derived from
`docs/engineering/total-system-inventory.md` and the M4 review artifacts in
`docs/roadmap/`.

Priorities: P0 = blocks acceptance, P1 = required for production readiness,
P2 = quality hardening, P3 = nice-to-have.

## Phase 1 — Baseline defects (P0)

| ID | Task | Dependency | Verification |
|----|------|------------|--------------|
| P0-1 | Fix CI smoke-test path: `ci.yml` compiles to `/tmp/nulq-amd64` but runs `./bin/nulq`. Change smoke step to `/tmp/nulq-amd64` or compile to `./bin/nulq`. | None | `go build -o /tmp/nulq-amd64 ./cmd/nulq && /tmp/nulq-amd64 version` |
| P0-2 | Create `docs/engineering/` directory with all 12 required documents (this plan is #2). | None | `ls docs/engineering/` contains 12 `.md` files |
| P0-3 | Add dedicated unit test for `internal/engine/store`. | Store package exists | `go test ./internal/engine/store/...` passes |
| P0-4 | Add dedicated unit test for `internal/platform/linux/systemd` collector. | Systemd collector exists | `go test ./internal/platform/linux/systemd/...` passes |

## Phase 2 — Test completeness (P0/P1)

| ID | Task | Dependency | Verification |
|----|------|------------|--------------|
| P1-1 | Run full test suite: `go test ./...` | All code compiled | Exit 0 |
| P1-2 | Run race detector: `go test -race ./...` | All code compiled | Exit 0 |
| P1-3 | Run `go vet ./...` | All code compiled | Exit 0 |
| P1-4 | Run `gofmt -l .` | All Go files | Empty output |
| P1-5 | Build linux/amd64 binary | `go build ./cmd/nulq` | Binary produced at `bin/nulq` |
| P1-6 | Build linux/arm64 cross-compile | `GOOS=linux GOARCH=arm64 go build ./cmd/nulq` | Binary produced |
| P1-7 | CLI smoke test: `nulq version`, `nulq rules list`, `nulq scan --format json` on synthetic fixture | P1-5 | Exit 0, valid JSON, 12 rules listed |
| P1-8 | Determinism test: two `--deterministic` scans on identical fixture produce byte-identical JSON | P1-5 | `diff` empty |
| P1-9 | Schema validation: JSON output validates against `schemas/nulq-report-v1.schema.json` | P1-7 | `jsonschema` or `go` validator passes |
| P1-10 | Benchmarks: `go test -bench=./...` | Test suite | Benchmarks run, no regressions |

## Phase 3 — Engineering documents (P1)

| ID | Document | Path | Dependency |
|----|----------|------|------------|
| P3-1 | Total system inventory | `docs/engineering/total-system-inventory.md` | P0-2 (done) |
| P3-2 | Total engineering plan | `docs/engineering/total-engineering-plan.md` | P0-2 (this file) |
| P3-3 | Feature test matrix | `docs/engineering/feature-test-matrix.md` | P1-1 |
| P3-4 | Integration test report | `docs/engineering/integration-test-report.md` | P1-7, P1-9 |
| P3-5 | Security semantics report | `docs/engineering/security-semantics-report.md` | P1-1 |
| P3-6 | Architecture review | `docs/engineering/architecture-review.md` | P1-1 |
| P3-7 | Performance report | `docs/engineering/performance-report.md` | P1-10 |
| P3-8 | Fuzzing report | `docs/engineering/fuzzing-report.md` | P1-1 |
| P3-9 | CLI contract report | `docs/engineering/cli-contract-report.md` | P1-7 |
| P3-10 | CI review | `docs/engineering/ci-review.md` | P0-1 |
| P3-11 | Remediation register | `docs/engineering/remediation-register.md` | All P0/P1 |
| P3-12 | Final engineering report | `docs/engineering/final-engineering-report.md` | All P3-1..P3-11 |

## Phase 4 — Lab (P2)

| ID | Task | Dependency | Verification |
|----|------|------------|--------------|
| P2-1 | Create Alpine lab Dockerfile at `lab/docker/alpine/Dockerfile` (pinned image, non-root user, dropped caps, no-new-privileges, read-only rootfs, no network, no host namespaces) | Docker available on host | `docker build` succeeds |
| P2-2 | Create lab fixtures at `lab/fixtures/` | P2-1 | Fixtures exist |
| P2-3 | Create lab manifest `lab/manifests/scenario-1.json` | P2-2 | Manifest validates via `lab.Validate()` |
| P2-4 | Run `make lab-build` and `make lab-test` | P2-1..P2-3 | All scenarios pass |

## Phase 5 — Release preparation (P3)

| ID | Task | Dependency | Verification |
|----|------|------------|--------------|
| P3-13 | `make release` | All previous phases | Release artifacts produced |
| P3-14 | `make verify` | P3-13 | Verification passes |
| P3-15 | `./bin/nulq version` and `./bin/nulq rules list` | P3-13 | Correct output |

## Dependency graph

```
P0-1 (CI fix) ──┐
                ▼
P0-2 (docs dir) → P3-1 (inventory) → P3-2 (plan) → P3-3..P3-12 (documents)
P0-3 (store test) → P1-1 (full test suite)
P0-4 (systemd test) → P1-1
P1-1 → P1-2 (race) → P1-3 (vet) → P1-4 (gofmt)
P1-4 → P1-5 (build amd64) → P1-6 (build arm64)
P1-5 → P1-7 (CLI smoke) → P1-8 (determinism) → P1-9 (schema)
P1-5 → P1-10 (benchmarks)
P1-7, P1-9 → P3-4 (integration report)
P1-1 → P3-5 (security semantics)
P1-1 → P3-6 (architecture review)
P1-10 → P3-7 (performance report)
P1-1 → P3-8 (fuzzing report)
P1-7 → P3-9 (CLI contract)
P0-1 → P3-10 (CI review)
All P0/P1 → P3-11 (remediation register)
All P3-1..P3-11 → P3-12 (final report)
P2-1 → P2-2 → P2-3 → P2-4 (lab)
P3-12 → P3-13 (release) → P3-14 (verify) → P3-15 (smoke)
```

## Acceptance criteria

The takeover is complete when:

1. `gofmt -l .` is empty.
2. `go vet ./...` passes.
3. `go test ./...` passes.
4. `go test -race ./...` passes.
5. `make build` produces `bin/nulq` (linux/amd64).
6. Cross-compile for linux/arm64 succeeds.
7. CLI smoke tests pass on synthetic fixtures.
8. `--deterministic` produces byte-identical JSON.
9. JSON output validates against `schemas/nulq-report-v1.schema.json`.
10. All 12 engineering documents exist in `docs/engineering/`.
11. CI smoke-test path defect is fixed and verified.
12. Remediation register accounts for every defect found during the takeover.

## Host safety

No host modification is required for any task in this plan. All tests use
synthetic fixtures under `t.TempDir()`. The lab, if Docker is available, uses
only pinned Alpine images with non-root users and no host namespaces. If Docker
is unavailable, Phase 4 is reported as a limitation, not skipped silently.

## Estimated effort

- Phase 1 (defects + docs dir): ~2 hours
- Phase 2 (test suite + builds + smoke): ~3 hours
- Phase 3 (12 documents): ~8 hours
- Phase 4 (lab, if Docker available): ~4 hours
- Phase 5 (release prep): ~2 hours

Total: ~19 hours, all executable without host modification.
