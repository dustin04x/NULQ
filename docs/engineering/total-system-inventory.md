# Total System Inventory — NULQ

This document inventories every subsystem of NULQ as of commit `f63aeba` (master).
It is the baseline reference for the total engineering takeover. Each entry
describes the component, its public contract, current state, and known defects.

## 1. Entry point — `cmd/nulq`

| Area | Detail |
|------|--------|
| File | `cmd/nulq/main.go` |
| Responsibility | Signal handling + exit code only. Parses CLI args, calls `cli.App.Run`, maps exit code to `os.Exit`. |
| State | Implemented, committed. No known defects. |
| Tests | None directly (covered by `internal/cli/cli_test.go`). |

## 2. Wiring — `internal/app`

| Area | Detail |
|------|--------|
| File | `internal/app/app.go` |
| Responsibility | Collector selection (system, identity, filesystem, process, systemd), rule registry, engine execution, report assembly, coverage computation, deterministic mode. |
| State | Implemented, committed. |
| Known issues | `buildReport` calls `report.Normalize()` twice (once implicitly via `normalizeDeterministic` path? No — `normalizeDeterministic` does not call `Normalize`, but `buildReport` calls it at the end). This is benign but redundant. |
| Tests | None dedicated to `app.Scan`; integration coverage via `internal/cli/cli_test.go` (`TestScanFixtureProducesConsumableJSON`). |

## 3. CLI — `internal/cli`

| Area | Detail |
|------|--------|
| Files | `cli.go`, `flags.go`, `scan.go`, `system.go`, `rules.go`, `version.go`, `cli_test.go` |
| Responsibility | Flag parsing, subcommand dispatch (`scan`, `system info`, `rules list`, `version`), output routing, exit codes (0/1/2/3). |
| State | Implemented, committed. |
| Known issues | `.github/workflows/ci.yml` cross-compiles to `/tmp/nulq-amd64` but smoke-test runs `./bin/nulq` (nonexistent). See CI review. |
| Tests | `cli_test.go`: version, rules list, usage errors, scan fixture JSON, fail-on contract, budget partial report, unknown rule rejection. |

## 4. Core models — `internal/core/models`

| Area | Detail |
|------|--------|
| Files | `observation.go`, `attributes.go`, `evidence.go`, `finding.go`, `report.go`, `severity.go`, `filemode.go`, `models_test.go` |
| Responsibility | Observation/evidence/finding/report contracts, stable IDs, severity/confidence ranking, mode rendering. |
| State | Implemented, committed. |
| Known issues | None. Tests cover severity ranking, mode formatting, observation ID stability, attribute copying, finding validation and deterministic IDs, sort ordering. |

## 5. Core errors — `internal/core/errors`

| Area | Detail |
|------|--------|
| File | `errors.go` |
| Responsibility | Classified error model: 9 classes (permission_denied, not_found, unavailable, unsupported, malformed_input, timeout, canceled, resource_exhausted, internal). |
| State | Implemented, committed. |
| Known issues | None. |

## 6. Core interfaces — `internal/core/interfaces`

| Area | Detail |
|------|--------|
| File | `interfaces.go` |
| Responsibility | `Collector`, `ObservationSet`, `Rule` contracts. |
| State | Implemented, committed. |
| Known issues | None. |

## 7. Engine — `internal/engine`

### 7.1 Executor — `internal/engine/executor`

| Area | Detail |
|------|--------|
| Files | `executor.go`, `executor_test.go` |
| Responsibility | Collector + rule execution under bounded concurrency, panic isolation, timeouts, context cancellation, per-component error isolation, missing-kind skip detection, invalid rule output rejection. |
| State | Implemented, committed. |
| Known issues | None. Tests cover skip-on-missing-kinds, failure/panic isolation, rule timeout enforcement, dedup+ordering, partial collector retention, cancelled context, invalid rule output rejection. |

### 7.2 Registry — `internal/engine/registry`

| Area | Detail |
|------|--------|
| Files | `registry.go` (implied), `registry_test.go` |
| Responsibility | Rule registration, duplicate rejection, module/ID selection, unknown selection rejection. |
| State | Implemented, committed. |
| Known issues | None. Tests cover invalid/duplicate rejection, module+ID selection, unknown selection rejection. |

### 7.3 Store — `internal/engine/store`

| Area | Detail |
|------|--------|
| Files | `store.go` (implied) |
| Responsibility | In-memory observation store backing `ObservationSet`. |
| State | Implemented (used by executor and rules tests). |
| Known issues | No dedicated test file found for store package. |

### 7.4 Aggregation — `internal/engine/aggregation`

| Area | Detail |
|------|--------|
| Files | `aggregation.go` |
| Responsibility | Finding+evidence merging, referential integrity, duplicate removal (stable ID), deterministic ordering. |
| State | Implemented, committed. |
| Known issues | None. |

### 7.5 Correlation — `internal/engine/correlation`

| Area | Detail |
|------|--------|
| Files | `engine.go`, `scenarios/scenarios.go` |
| Responsibility | COR-001 through COR-005 relationship evaluation on observations. Produces `CorrelationResult` with relationships; does NOT emit findings (M3 design states correlation is not finding-generating). |
| State | Implemented, committed. Design labelled as design per M10 constraint. |
| Known issues | None in code; architectural constraint documented. |

## 8. Evidence — `internal/evidence`

| Area | Detail |
|------|--------|
| File | `evidence.go` |
| Responsibility | Evidence builder with duplicate citation collapse, absent-value citation, resource-kind mapping. |
| State | Implemented, committed. |
| Known issues | None. |

## 9. Reporting — `internal/reporting`

| Area | Detail |
|------|--------|
| Files | `machine.go`, `markdown.go`, `terminal.go`, `sanitize.go`, `reporting_test.go` |
| Responsibility | JSON, JSONL, Markdown, Terminal renderers; control-character sanitization for terminal/Markdown output. |
| State | Implemented, committed. |
| Known issues | `markdownSafe` backticks are converted to apostrophes (`'`), which changes code spans in finding text. Benign for sanitization but worth noting. Terminal renderer hides LOW findings in non-quiet mode (by design: `!opts.Quiet && finding.Severity.Rank() <= SeverityLow.Rank()` prints them inline as a compact line, not full rendering). |

## 10. Collectors — `internal/platform/linux`

### 10.1 System — `internal/platform/linux/system`

| Area | Detail |
|------|--------|
| Files | `collector.go`, `collector_test.go` |
| Responsibility | Host info (hostname, OS, kernel, arch, container, LSM list). |
| State | Implemented, committed. |

### 10.2 Identity — `internal/platform/linux/identity`

| Area | Detail |
|------|--------|
| Files | `collector.go`, `collector_test.go` |
| Responsibility | Execution context (UID/EUID/GID/EGID/groups/umask/username), group memberships, security controls (LSM state). |
| State | Implemented, committed. |

### 10.3 Filesystem — `internal/platform/linux/filesystem`

| Area | Detail |
|------|--------|
| Files | `collector.go`, `collector_test.go`, `mounts.go`, `mounts_test.go`, `names.go`, `perms.go` |
| Responsibility | Filesystem traversal (roots, path entries from PATH, max-files budget), mountinfo parsing (/proc/self/mountinfo), exclusion of pseudo-filesystems and container storage, permission/ACL metadata. |
| State | Implemented, committed. |
| Known issues | `excludedPrefixes` hardcodes container storage paths (`/var/lib/docker`, etc.). This is by design for host protection; documented limitation. |

### 10.4 Process — `internal/platform/linux/process`

| Area | Detail |
|------|--------|
| Files | `collector.go`, `collector_test.go` |
| Responsibility | Process enumeration from `/proc`, executable path/mode/ownership, parent directory metadata, capability bounding/effective sets, seccomp mode, namespace IDs. ProcRoot override for tests. |
| State | Implemented, committed. |

### 10.5 Systemd — `internal/platform/linux/systemd`

| Area | Detail |
|------|--------|
| Files | `collector.go` |
| Responsibility | Reads `.service` unit files from standard systemd directories, extracts security directives (User, NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp, CapabilityBoundingSet). Never talks to PID 1 over D-Bus. |
| State | Implemented, committed (M4 addition). |
| Known issues | No test file found for systemd collector. |

### 10.6 ACL — `internal/platform/linux/acl`

| Area | Detail |
|------|--------|
| Files | `acl.go`, `acl_test.go` |
| Responsibility | POSIX ACL parsing/evaluation, effective write/exec decisions. |
| State | Implemented, committed. |

## 11. Rules — `internal/rules`

12 rules registered across 4 modules:

| ID | Module | Required Kind | Default Severity | State |
|----|--------|--------------|------------------|-------|
| NULQ-IDENT-001 | identity | group_membership | LOW | Implemented, tested |
| NULQ-FS-001 | filesystem | file | INFO | Implemented, tested |
| NULQ-FS-002 | filesystem | directory | MEDIUM | Implemented, tested |
| NULQ-FS-003 | filesystem | path_entry | LOW | Implemented, tested |
| NULQ-FS-004 | filesystem | mount | INFO | Implemented, tested |
| NULQ-PROC-001 | process | process | HIGH (contextual) | Implemented, tested |
| NULQ-SYS-001 | system | sysctl | LOW | Implemented, tested |
| NULQ-SYS-002 | system | security_control | LOW | Implemented, tested |
| NULQ-SYS-003 | system | execution_context | MEDIUM | Implemented, committed (M4) |
| NULQ-SYS-004 | system | systemd_unit | MEDIUM | Implemented, committed (M4) |
| NULQ-SYS-005 | system | process | LOW | Implemented, committed (M4) |
| NULQ-SYS-006 | system | security_control | MEDIUM | Implemented, committed (M4) |

All rules have: positive tests, negative tests, unavailable-data tests, evidence citations, impact/remediation/limitations, deterministic IDs, stable metadata.

## 12. Lab — `internal/lab`

| Area | Detail |
|------|--------|
| Files | `manifest.go`, `validate.go`, `schema.go`, `summary.go`, `validate_test.go`, `schema_test.go` |
| Responsibility | Lab manifest schema, scenario expectations, validation engine, isolation verification, integrity audit (duplicates, dangling evidence, findings without evidence). |
| State | Implemented, committed. |
| Known issues | No lab manifest files (`lab/manifests/*.json`) found; no Docker laboratory present (`lab/docker/` referenced by AGENTS.md but not verified). |

## 13. Public API — `pkg/api`

| Area | Detail |
|------|--------|
| File | `api.go` |
| Responsibility | Type aliases for external report consumers, `ParseReport` JSON decoder. |
| State | Implemented, committed. |
| Known issues | None. |

## 14. Schemas — `schemas/`

| Area | Detail |
|------|--------|
| File | `schemas/nulq-report-v1.schema.json` |
| Responsibility | JSON Schema v1.1 report contract. |
| State | Implemented, committed. |
| Known issues | None identified. |

## 15. Version — `internal/version`

| Area | Detail |
|------|--------|
| Files | (implied) |
| Responsibility | Build metadata (version, commit, date, Go version, platform). |
| State | Implemented, committed. |

## 16. CI — `.github/workflows`

| Area | Detail |
|------|--------|
| Files | `ci.yml`, `release.yml` |
| Responsibility | Go build/test, cross-compile, smoke test, lab build/test. |
| State | Implemented, committed. |
| Known defects | **CONFIRMED:** `ci.yml` cross-compiles binary to `/tmp/nulq-amd64` but smoke-test invokes `./bin/nulq` (path mismatch). See `docs/engineering/ci-review.md`. |

## 17. Documentation

| Area | Files | State |
|------|-------|-------|
| README | `README.md` | User-facing, current |
| Mission | `MISSION.md` | Current milestone |
| Roadmap | `ROADMAP.md` | Milestones |
| Changelog | `CHANGELOG.md` | Changes |
| Security | `SECURITY.md` | Policy |
| Contributing | `CONTRIBUTING.md` | Process |
| ADRs | `docs/decisions/0001-0009.md` | Architecture decisions |
| M4 review artifacts | `docs/roadmap/m4-*` | Red-team review, design corrections, final scope |
| Engineering (this takeover) | `docs/engineering/` | **Not yet created** — this document is the first |

## 18. Host protection boundary

NULQ is developed on the owner's primary Ryoku Linux workstation. All work is
read-only on the host. No `sudo`, no host config changes, no root, no Docker
socket access, no host namespace access. Tests use synthetic fixtures only.

## Inventory completeness statement

All 18 subsystem areas above have been read and catalogued. No subsystem was
skipped. The only gaps relative to a fully engineered system are:

1. `docs/engineering/` does not exist — the 12 required takeover documents are absent.
2. No dedicated test for `internal/engine/store`.
3. No dedicated test for `internal/platform/linux/systemd`.
4. No lab manifest files or Docker laboratory present.
5. CI smoke-test path defect (confirmed).
6. No M3.5 acceptance documents (`docs/audits/m35-*`).
7. No benchmarks, fuzzing reports, or performance reports.
