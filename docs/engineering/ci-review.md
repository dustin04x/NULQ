# CI Review — NULQ

This report reviews NULQ's CI configuration (`.github/workflows/ci.yml`)
and documents defects found and fixes applied during this engineering
takeover.

## 1. CI workflow structure

| Job | Trigger | Timeout | Steps |
|-----|---------|---------|-------|
| verify | push, PR to master | 30 min | gofmt, vet, test, race test, cross-compile amd64, cross-compile arm64, smoke test, fail-on contract, README check |
| release | push to master | 60 min | cross-compile amd64+arm64 with ldflags, verify binaries, upload artifacts |

## 2. Defects found and fixed

### Defect CI-001: Smoke-test binary path mismatch (P0)

**Symptom**: The "Cross-compile Linux AMD64" step builds the binary to
`/tmp/nulq-amd64`, but the "Smoke test the binary (AMD64)" step invokes
`./bin/nulq`, which does not exist. The smoke test always fails.

**Location**: `.github/workflows/ci.yml:63-66`

**Fix**: Changed `./bin/nulq` to `/tmp/nulq-amd64` in all four smoke-test
invocations (version, rules list, system info, scan).

**Fix verification**: Local build and smoke test of `/tmp/nulq-amd64` (or
`bin/nulq`) confirmed working:
- `/tmp/nulq-amd64 version` → valid output
- `/tmp/nulq-amd64 rules list --format json` → 12 rules
- `/tmp/nulq-amd64 scan --root <fixture> --format json` → valid JSON report

### Defect CI-002: Fail-on test uses empty fixture directory (P0)

**Symptom**: The fail-on threshold contract test creates
`$FIXTURE_ROOT` (`/tmp/nulq-ci-test-root`) but never populates it with
fixture files. An empty directory produces no findings, so `--fail-on info`
exits 0 instead of the expected 3. The test would always fail.

**Location**: `.github/workflows/ci.yml:81-98`

**Fix**: Added `mkdir -p "$FIXTURE_ROOT/shared"` and `chmod 777` to create
a world-writable directory, which produces a MEDIUM finding from
NULQ-FS-002. This satisfies the expected contract:
- `--fail-on info/low/medium` → exit 3 (MEDIUM >= threshold)
- `--fail-on high/critical` → exit 0 (MEDIUM < threshold)

**Fix verification**: Local test with a world-writable directory fixture
confirmed the fail-on contract behaves as documented.

## 3. CI coverage assessment

| Check | Present | Passing locally |
|-------|---------|-----------------|
| gofmt -l . | Yes | Yes |
| go vet ./... | Yes | Yes |
| go test ./... | Yes | Yes |
| go test -race ./... | Yes | Yes |
| Cross-compile amd64 | Yes | Yes |
| Cross-compile arm64 | Yes | Yes |
| Smoke test binary | Yes (was broken) | Yes (fixed) |
| Fail-on contract | Yes (was broken) | Yes (fixed) |
| README exit codes | Yes | Yes |
| Lab build/test | No | Not configured |
| Release build | Yes | Yes |
| `make build` | No | Not referenced |
| `make lab-build` | No | Not referenced |
| `make lab-test` | No | Not referenced |

## 4. Missing CI coverage

| Gap | Impact | Plan |
|-----|--------|------|
| No `make lab-build` / `make lab-test` | Lab not validated in CI | Add Docker lab steps when Docker is available |
| No `make build` target | Build not centralized | Add Makefile if missing |
| No security scanning (saudit, govulncheck) | Dependency/vulnerability not checked | Standard library only reduces need |
| No cross-platform test matrix | Only ubuntu-latest | Consider additional runners |
| No fuzzing in CI | Parser fuzzing not automated | Add fuzzing when tests exist |

## 5. Recommendations

1. Add `make lab-build` and `make lab-test` targets to CI when Docker
   laboratory is available.
2. Add a `Makefile` with `build`, `test`, `lint`, `lab-build`, `lab-test`
   targets for centralized command entry points.
3. Consider adding `go vulncheck` for dependency scanning (low priority
   since standard library only).
4. Add benchmark comparison to detect performance regressions.

## 6. Conclusion

CI workflow is structurally sound but had two defects (both P0) that would
cause pipeline failure. Both are fixed in this takeover. The workflow
adequately covers gofmt, vet, test, race, cross-compilation, and smoke
testing. Lab validation is not yet integrated.
