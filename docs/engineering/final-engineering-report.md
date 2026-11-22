# Final Engineering Report — NULQ

This report is the conclusion of the total engineering takeover of NULQ.
It consolidates findings from all prior engineering documents, states the
verification record, and delivers the final acceptance verdict.

## 1. Executive summary

NULQ is a well-architected, read-only Linux privilege-boundary discovery
framework with 12 detection rules across 4 modules, a concurrent execution
engine with failure isolation, deterministic output, evidence-backed
findings, and a published JSON Schema v1.1 report contract. All unit tests
pass, the race detector is clean, `go vet` and `gofmt` are clean, and the
binary builds for linux/amd64 and linux/arm64.

Three P0 defects were found and fixed during this takeover:
- CI smoke-test binary path mismatch (ci.yml)
- CI fail-on test empty fixture (ci.yml)
- Deterministic mode omitted evidence timestamps (app.go)

All 12 required engineering documents have been created in `docs/engineering/`.

## 2. Verification record

| Check | Command | Result |
|-------|---------|--------|
| Formatting | `gofmt -l .` | Empty |
| Static analysis | `go vet ./...` | Pass |
| Unit tests | `go test ./...` | Pass (all packages) |
| Race detector | `go test -race ./...` | Pass |
| Build linux/amd64 | `go build -o bin/nulq ./cmd/nulq` | Pass |
| Build linux/arm64 | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq` | Pass |
| CLI smoke: version | `bin/nulq version` | Pass |
| CLI smoke: rules list | `bin/nulq rules list --format json` | Pass (12 rules) |
| CLI smoke: scan | `bin/nulq scan --root <fixture> --format json` | Pass (valid JSON) |
| CLI smoke: fail-on | `--fail-on medium` → exit 3, `--fail-on high` → exit 0 | Pass |
| Determinism | `--deterministic` byte-identical JSON | Pass |
| Schema validation | v1.1 structure valid | Pass |
| Referential integrity | All evidence IDs resolve | Pass |

## 3. Documents created

| # | Document | Path |
|---|----------|------|
| 1 | Total system inventory | docs/engineering/total-system-inventory.md |
| 2 | Total engineering plan | docs/engineering/total-engineering-plan.md |
| 3 | Feature test matrix | docs/engineering/feature-test-matrix.md |
| 4 | Integration test report | docs/engineering/integration-test-report.md |
| 5 | Security semantics report | docs/engineering/security-semantics-report.md |
| 6 | Architecture review | docs/engineering/architecture-review.md |
| 7 | Performance report | docs/engineering/performance-report.md |
| 8 | Fuzzing report | docs/engineering/fuzzing-report.md |
| 9 | CLI contract report | docs/engineering/cli-contract-report.md |
| 10 | CI review | docs/engineering/ci-review.md |
| 11 | Remediation register | docs/engineering/remediation-register.md |
| 12 | Final engineering report | docs/engineering/final-engineering-report.md |

## 4. Code changes made

| File | Change | Reason |
|------|--------|--------|
| internal/app/app.go | Added evidence `CollectedAt` normalization to `normalizeDeterministic` | Deterministic output was broken for evidence timestamps |
| .github/workflows/ci.yml | Changed smoke test from `./bin/nulq` to `/tmp/nulq-amd64` | Binary path mismatch caused CI failure |
| .github/workflows/ci.yml | Added fixture creation (chmod 777 directory) to fail-on test | Empty directory produced no findings, test always failed |

## 5. Known gaps and limitations

| Area | Gap | Severity | Plan |
|------|-----|----------|------|
| Tests | No dedicated test for `internal/engine/store` | Low | Add store_test.go |
| Tests | No dedicated test for `internal/platform/linux/systemd` | Low | Add systemd collector test |
| Tests | No dedicated test for `internal/evidence` | Low | Add evidence builder test |
| Testing | No benchmark tests | Medium | Add BenchmarkScan, BenchmarkCollector |
| Testing | No fuzzing tests | Medium | Add mountinfo/ACL parser fuzzing |
| Lab | No lab manifest files | High | Create lab/manifests/*.json |
| Lab | No Docker laboratory | Medium | Create lab/docker/alpine/Dockerfile |
| CI | No lab-build/lab-test in CI | Medium | Add when lab is ready |
| CLI | `--output`, `--color`, `--module` not tested at CLI level | Low | Add CLI integration tests |
| Exit codes | Exit code 1 not directly tested | Low | Add runtime error test |

## 6. Host impact statement

No host resources were modified during this takeover. All tests used
synthetic fixtures under `t.TempDir()`. No `sudo`, `doas`, `su`, or elevated
privileges were used. No host configuration, ownership, permissions, or
system directories were modified. No Docker resources outside NULQ's scope
were touched.

## 7. Acceptance verdict

**ENGINEERING ACCEPTED**

The codebase is production-ready for its intended scope: read-only Linux
privilege-boundary discovery with 12 detection rules, deterministic output,
evidence-backed findings, and a stable JSON Schema v1.1 contract. All
verification gates pass. Three P0 defects were fixed. Remaining gaps are
documented in the remediation register and do not block acceptance.

### Conditions for future releases

1. Create M3.5 acceptance documents before declaring M4.1/M4.2 complete.
2. Add dedicated tests for store, systemd collector, and evidence builder.
3. Create lab manifests and Docker laboratory before the next milestone.
4. Add benchmarks and fuzzing for parser hardening.
5. Run `make release` and `make verify` before tagging a release.

## 8. Sign-off

- Engineering takeover: complete
- All 12 engineering documents: created
- All verification gates: passed
- All P0 defects: fixed
- Verdict: **ENGINEERING ACCEPTED**
