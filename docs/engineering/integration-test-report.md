# Integration Test Report — NULQ

This report documents integration-level verification of NULQ: end-to-end
pipeline execution through `app.Scan`, CLI smoke tests, schema validation,
and determinism checks. All tests were run against synthetic fixtures under
`t.TempDir()` — no host resources were inspected or modified.

## 1. Test environment

| Property | Value |
|----------|-------|
| Go version | go1.27.4-X:nodwarf5 |
| Target | linux/amd64 |
| Module | github.com/dustin04x/nulq |
| Dependency mode | standard library only |
| Commit | f63aeba |

## 2. Unit test results

| Package | Result | Notes |
|---------|--------|-------|
| internal/app | ok | Scan wiring |
| internal/cli | ok | CLI contract, fail-on, fixtures |
| internal/core/models | ok | IDs, severity, modes, sorting |
| internal/engine/aggregation | ok | Merge, dedup, ordering |
| internal/engine/executor | ok | Concurrency, timeouts, panic isolation |
| internal/engine/registry | ok | Registration, selection |
| internal/lab | ok | Manifest validation, integrity audit |
| internal/platform/linux/acl | ok | ACL parsing/evaluation |
| internal/platform/linux/filesystem | ok | Mountinfo, traversal, exclusions |
| internal/platform/linux/identity | ok | Execution context, groups, controls |
| internal/platform/linux/process | ok | Process enumeration, capabilities |
| internal/platform/linux/system | ok | Host info, LSM list |
| internal/reporting | ok | JSON, JSONL, Markdown, Terminal, sanitization |
| internal/rules/filesystem | ok | SUID, world-writable, path entry, mount flags |
| internal/rules/identity | ok | Privileged groups |
| internal/rules/process | ok | Writable parent, ACL, mount constraints |
| internal/rules/system | ok | Sysctl, MAC, capabilities, seccomp, systemd, userns |
| tests/integration | ok | End-to-end pipeline on fixtures |

Packages without test files: cmd/nulq, core/errors, core/interfaces,
engine/correlation, engine/correlation/scenarios, engine/store, evidence,
platform/linux/systemd, rules (package), version, lab/verify, pkg/api.

## 3. Race detector

`go test -race ./...` — all packages pass. No data races detected.

## 4. Static analysis

`go vet ./...` — clean, no issues.
`gofmt -l .` — empty, all files properly formatted.

## 5. Build verification

| Build | Command | Result |
|-------|---------|--------|
| linux/amd64 | `go build -o bin/nulq ./cmd/nulq` | Pass |
| linux/arm64 | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq` | Pass |

## 6. CLI smoke tests

All commands executed against a synthetic fixture containing:
- A setuid root-owned executable (`/usr/bin/privtool`, mode 4755)
- A world-writable directory (`/data`, mode 0777)

| Command | Exit code | Output valid | Notes |
|---------|-----------|--------------|-------|
| `nulq version` | 0 | Yes | Prints version metadata |
| `nulq version --format json` | 0 | Yes | Valid JSON, name="nulq" |
| `nulq rules list --format json` | 0 | Yes | 12 rules listed |
| `nulq scan --root <fixture> --format json --modules filesystem` | 0 | Yes | 7 findings, 31 evidence items, 74 observations |
| `nulq scan --format json --fail-on medium` | 3 | — | MEDIUM >= MEDIUM |
| `nulq scan --format json --fail-on high` | 0 | — | MEDIUM < HIGH |
| `nulq scan --format json --fail-on critical` | 0 | — | MEDIUM < CRITICAL |
| `nulq scan --max-files 1` | 0 | Yes | Partial coverage reported |
| `nulq scan --rules NULQ-NOPE-999` | 2 | — | Unknown rule = usage error |

## 7. Determinism

Two `--deterministic` scans of the same fixture produced byte-identical JSON
output. All timestamps (scan, findings, observations, evidence) are normalized
to the deterministic reference. Duration is set to 0. Report ID is derived
from hostname + zero time.

**Defect fixed during this takeover:** `normalizeDeterministic` previously
omitted evidence `CollectedAt` timestamps, causing non-deterministic output.
Fixed in `internal/app/app.go:241-243`.

## 8. Schema validation

Report output conforms to `schemas/nulq-report-v1.schema.json` (v1.1):
- `schema_version` = "1.1"
- `tool` object with name, version, go_version, platform
- `host` object with hostname, os_id, os_name, kernel_release, architecture
- `scan` object with report_id, started_at, finished_at, duration_ms, modules
- `findings` array (non-null)
- `evidence` array (non-null)
- `stats` object with observations, findings, evidence, rules, collectors
- `coverage` object with execution_complete, coverage_complete, status
- `limitations` array

All required fields present. No extra fields that would fail strict decoding.

## 9. Referential integrity

Every finding cites at least one evidence ID. Every cited evidence ID
resolves to an evidence item in the same report. No dangling references.
No duplicate finding IDs.

## 10. Coverage classification

| Scan type | execution_complete | coverage_complete | Status |
|-----------|-------------------|-------------------|--------|
| Full scan (all modules) | true | true | complete |
| Budget-truncated scan | true | false | partial |
| Collector failure | false | — | failed |

## 11. Gaps

| Gap | Impact | Plan |
|-----|--------|------|
| No lab manifest files (`lab/manifests/*.json`) | Lab scenarios cannot execute | Create manifests + Docker lab |
| No integration test for `--observations` flag | Observation output path untested at CLI level | Add CLI test |
| No integration test for `--output` file flag | File output path untested at CLI level | Add CLI test |
| No cross-module integration test (e.g. filesystem + process together) | Multi-module correlation untested | Add integration test |

## Conclusion

Integration tests pass. The pipeline is deterministic, schema-conformant,
and referentially intact. Remaining gaps are lab manifests and a few CLI
flag integration paths.
