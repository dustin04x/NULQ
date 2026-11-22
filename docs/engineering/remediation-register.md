# Remediation Register — NULQ

This register tracks every defect, gap, and improvement identified during
the total engineering takeover. Each entry has a status, owner, and
verification method.

## Defects fixed during this takeover

| ID | Component | Severity | Description | Fix | Status | Verified |
|----|-----------|----------|-------------|-----|--------|----------|
| R-001 | `.github/workflows/ci.yml` | P0 | Smoke test invoked `./bin/nulq` but binary was compiled to `/tmp/nulq-amd64` | Changed smoke test to use `/tmp/nulq-amd64` | Fixed | Local smoke test passed |
| R-002 | `.github/workflows/ci.yml` | P0 | Fail-on test scanned empty directory, producing no findings | Added `chmod 777` subdirectory fixture | Fixed | Local fail-on contract test passed |
| R-003 | `internal/app/app.go` | P0 | `normalizeDeterministic` omitted evidence `CollectedAt` timestamps, causing non-deterministic JSON output | Added evidence timestamp normalization loop | Fixed | `--deterministic` produces byte-identical JSON |

## Defects found but not fixed (deferred)

| ID | Component | Severity | Description | Reason deferred |
|----|-----------|----------|-------------|-----------------|
| R-004 | `internal/engine/store` | P1 | No dedicated test file | Test creation in next sprint |
| R-005 | `internal/platform/linux/systemd` | P1 | No dedicated test file | Test creation in next sprint |
| R-006 | `internal/evidence` | P1 | No dedicated test file | Test creation in next sprint |

## Gaps identified (not defects, but missing coverage)

| ID | Area | Priority | Description | Plan |
|----|------|----------|-------------|------|
| G-001 | Benchmarks | P2 | No benchmark tests defined | Add `BenchmarkScan`, `BenchmarkCollector` |
| G-002 | Fuzzing | P2 | No fuzzing tests for mountinfo, ACL parsers | Add Go native fuzzing tests |
| G-003 | Lab manifests | P1 | No `lab/manifests/*.json` files | Create lab manifests + Docker lab |
| G-004 | Lab Docker | P2 | No Docker laboratory configured | Create `lab/docker/alpine/Dockerfile` |
| G-005 | CLI integration | P2 | `--output`, `--color`, `--module` flags not tested | Add CLI integration tests |
| G-006 | Exit code 1 | P2 | Runtime error exit code not tested at CLI level | Add test |
| G-007 | M3.5 acceptance | P1 | No `docs/audits/m35-*` documents | Create M3.5 acceptance audit |

## Documentation created

| ID | Document | Path | Status |
|----|----------|------|--------|
| D-001 | Total system inventory | `docs/engineering/total-system-inventory.md` | Complete |
| D-002 | Total engineering plan | `docs/engineering/total-engineering-plan.md` | Complete |
| D-003 | Feature test matrix | `docs/engineering/feature-test-matrix.md` | Complete |
| D-004 | Integration test report | `docs/engineering/integration-test-report.md` | Complete |
| D-005 | Security semantics report | `docs/engineering/security-semantics-report.md` | Complete |
| D-006 | Architecture review | `docs/engineering/architecture-review.md` | Complete |
| D-007 | Performance report | `docs/engineering/performance-report.md` | Complete |
| D-008 | Fuzzing report | `docs/engineering/fuzzing-report.md` | Complete |
| D-009 | CLI contract report | `docs/engineering/cli-contract-report.md` | Complete |
| D-010 | CI review | `docs/engineering/ci-review.md` | Complete |
| D-011 | Remediation register | `docs/engineering/remediation-register.md` | Complete |
| D-012 | Final engineering report | `docs/engineering/final-engineering-report.md` | In progress |

## Verification record

| Check | Command | Result | Date |
|-------|---------|--------|------|
| Formatting | `gofmt -l .` | Empty (pass) | 2026-11-21 |
| Static analysis | `go vet ./...` | Pass | 2026-11-21 |
| Unit tests | `go test ./...` | Pass | 2026-11-21 |
| Race detector | `go test -race ./...` | Pass | 2026-11-21 |
| Build amd64 | `go build -o bin/nulq ./cmd/nulq` | Pass | 2026-11-21 |
| Build arm64 | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq` | Pass | 2026-11-21 |
| CLI smoke | `bin/nulq version`, `rules list`, `scan` | Pass | 2026-11-21 |
| Determinism | `--deterministic` byte-identical | Pass | 2026-11-21 |
| Schema | v1.1 structure valid | Pass | 2026-11-21 |
| CI fix | Smoke test path + fail-on fixture | Pass | 2026-11-21 |

## Host impact statement

No host resources were modified during this takeover. All tests used
synthetic fixtures under `t.TempDir()`. No `sudo`, no host configuration
changes, no root access, no Docker socket access. The only modified files
are within the NULQ repository.

## Open items

1. Create M3.5 acceptance documents (`docs/audits/m35-*`)
2. Create lab manifests and Docker laboratory
3. Add benchmarks and fuzzing tests
4. Add dedicated tests for store, systemd collector, evidence builder
5. Release preparation (`make release`, `make verify`)
