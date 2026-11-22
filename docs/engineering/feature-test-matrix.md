# Feature Test Matrix — NULQ

This matrix maps every user-facing feature and CLI contract to its test
coverage. It is the authoritative record of what is verified and what is not.

## 1. CLI commands

| Feature | Command | Unit test | Integration test | Manual smoke | Status |
|---------|---------|-----------|------------------|--------------|--------|
| Version (text) | `nulq version` | cli_test.go:TestVersionCommand | — | Yes | Pass |
| Version (JSON) | `nulq version --format json` | cli_test.go:TestVersionCommand | — | Yes | Pass |
| Rules list (JSON) | `nulq rules list --format json` | cli_test.go:TestRulesListCommand | — | Yes | Pass |
| Rules list (module filter) | `nulq rules list --module <mod>` | cli_test.go:TestUsageErrors (invalid) | — | — | — |
| Scan (JSON) | `nulq scan --format json` | cli_test.go:TestScanFixtureProducesConsumableJSON | tests/integration | Yes | Pass |
| Scan (terminal) | `nulq scan` | — | — | Yes | — |
| Scan (markdown) | `nulq scan --format markdown` | — | — | — | — |
| Scan (JSONL) | `nulq scan --format jsonl` | — | — | — | — |
| Scan (output file) | `nulq scan --output report.json` | — | — | — | — |
| Scan (observations) | `nulq scan --observations` | — | — | — | — |
| Scan (deterministic) | `nulq scan --deterministic` | — | — | Yes | Pass |
| Scan (fail-on) | `nulq scan --fail-on <sev>` | cli_test.go:TestScanFailOnContract / TestScanFailOnContractCoverages / TestScanFailOnNoFindings | — | — | Pass |
| Scan (max-files budget) | `nulq scan --max-files N` | cli_test.go:TestScanBudgetProducesPartialReport | — | — | Pass |
| Scan (root filter) | `nulq scan --root <path>` | cli_test.go (fixtureRoot) | — | Yes | Pass |
| Scan (module filter) | `nulq scan --modules <mods>` | cli_test.go:TestScanFixtureProducesConsumableJSON | — | Yes | Pass |
| Scan (rule filter) | `nulq scan --rules <ids>` | cli_test.go:TestScanRejectsUnknownRule | — | — | Pass |
| Scan (concurrency) | `nulq scan --concurrency N` | — | — | — | — |
| Scan (rule timeout) | `nulq scan --rule-timeout D` | executor_test.go:TestEnforcesRuleTimeout | — | — | Pass |
| Scan (collector timeout) | `nulq scan --collector-timeout D` | — | — | — | — |
| Scan (total timeout) | `nulq scan --timeout D` | — | — | — | — |
| Scan (quiet) | `nulq scan --quiet` | reporting_test.go:TestQuietTerminalHidesLowSeverity | — | — | Pass |
| Scan (color) | `nulq scan --color <mode>` | — | — | — | — |
| Scan (verbose) | `nulq scan --verbose` | — | — | — | — |
| System info | `nulq system info` | — | — | Yes | — |
| System info (JSON) | `nulq system info --format json` | — | — | — | — |
| Help | `nulq help` / `nulq -h` | cli_test.go:TestUsageErrors | — | — | Pass |
| Unknown command | `nulq <bogus>` | cli_test.go:TestUsageErrors | — | — | Pass |

## 2. Exit codes

| Code | Meaning | Test | Status |
|------|---------|------|--------|
| 0 | Success | cli_test.go:TestVersionCommand, TestScanFixtureProducesConsumableJSON | Pass |
| 1 | Runtime error | — | — |
| 2 | Usage error | cli_test.go:TestUsageErrors, TestScanRejectsUnknownRule | Pass |
| 3 | Findings at/above threshold | cli_test.go:TestScanFailOnContract, TestScanFailOnContractCoverages | Pass |

## 3. Report formats

| Format | Renderer | Test | Schema validated | Status |
|--------|----------|------|------------------|--------|
| JSON | reporting.JSON | reporting_test.go:TestJSONIsMachineReadableAndVersioned | Yes (manual) | Pass |
| JSONL | reporting.JSONL | reporting_test.go:TestJSONLEmitsOneObjectPerLine | — | Pass |
| Markdown | reporting.Markdown | reporting_test.go:TestMarkdownIncludesFindingsAndLimitations | — | Pass |
| Terminal | reporting.Terminal | reporting_test.go:TestTerminalStripsInjectedEscapesAndShowsRemediation | — | Pass |

## 4. Sanitization

| Feature | Test | Status |
|---------|------|--------|
| Control char removal (singleLine) | reporting_test.go (escape injection in JSON) | Pass |
| Control char removal (multiLine) | reporting_test.go (escape injection in terminal) | Pass |
| Markdown table escaping | reporting_test.go (no escape sequences in markdown) | Pass |
| No ANSI in JSON output | reporting_test.go:TestJSONIsMachineReadableAndVersioned | Pass |
| No ANSI in terminal (color=never) | reporting_test.go:TestTerminalStripsInjectedEscapesAndShowsRemediation | Pass |

## 5. Engine

| Feature | Test | Status |
|---------|------|--------|
| Collector concurrency | executor_test.go | Pass |
| Rule concurrency | executor_test.go | Pass |
| Panic isolation (collector) | executor_test.go:TestIsolatesRuleFailureAndPanic | Pass |
| Panic isolation (rule) | executor_test.go:TestIsolatesRuleFailureAndPanic | Pass |
| Rule timeout | executor_test.go:TestEnforcesRuleTimeout | Pass |
| Cancelled context | executor_test.go:TestCancelledContextStopsRun | Pass |
| Skip on missing observations | executor_test.go:TestSkipsRuleWithoutRequiredObservations | Pass |
| Partial collector retention | executor_test.go:TestKeepsObservationsFromPartialCollector | Pass |
| Invalid rule output rejection | executor_test.go:TestRejectsInvalidRuleOutput | Pass |
| Finding dedup + ordering | executor_test.go:TestDeduplicatesAndOrdersFindings | Pass |

## 6. Registry

| Feature | Test | Status |
|---------|------|--------|
| Invalid metadata rejection | registry_test.go:TestRegistryRejectsInvalidAndDuplicateRules | Pass |
| Duplicate rule rejection | registry_test.go:TestRegistryRejectsInvalidAndDuplicateRules | Pass |
| Module selection | registry_test.go:TestRegistrySelectsByModuleAndID | Pass |
| ID selection | registry_test.go:TestRegistrySelectsByModuleAndID | Pass |
| Unknown module rejection | registry_test.go:TestRegistryRejectsUnknownSelection | Pass |
| Unknown rule ID rejection | registry_test.go:TestRegistryRejectsUnknownSelection | Pass |

## 7. Rules

| Rule ID | Required kind | Positive test | Negative test | Unavailable test | Status |
|---------|--------------|---------------|---------------|------------------|--------|
| NULQ-IDENT-001 | group_membership | identity_test.go | identity_test.go:TestPrivilegedGroupRuleIgnoresUnknownGroups | — | Pass |
| NULQ-FS-001 | file | fs_test.go:TestSUIDRuleSeverityIsContextual | fs_test.go:TestSUIDRuleIgnoresOrdinaryFiles | — | Pass |
| NULQ-FS-002 | directory | fs_test.go:TestWorldWritableRuleIsContextual | fs_test.go (sticky dir) | — | Pass |
| NULQ-FS-003 | path_entry | fs_test.go:TestPathEntryRuleCases | fs_test.go (not writable) | fs_test.go (missing entry) | Pass |
| NULQ-FS-004 | mount | fs_test.go:TestMountFlagsRuleIsContextual | fs_test.go (no nosuid) | — | Pass |
| NULQ-PROC-001 | process | proc_test.go:TestWritableParentRuleCases | proc_test.go (protected parent) | proc_test.go (unreadable) | Pass |
| NULQ-SYS-001 | sysctl | system_test.go:TestSysctlRuleReportsOnlyDeviations | system_test.go (hardened) | system_test.go:TestSysctlRuleSkipsUnavailableParameters | Pass |
| NULQ-SYS-002 | security_control | system_test.go:TestMACRuleDetectsMissingControl | system_test.go:TestMACRuleAppArmorAloneIsSilent | system_test.go:TestMACRuleStaysSilentWhenEnforcingOrUnknown | Pass |
| NULQ-SYS-003 | execution_context | — | — | — | Not lab-tested |
| NULQ-SYS-004 | systemd_unit | — | — | — | Not lab-tested |
| NULQ-SYS-005 | process | — | — | — | Not lab-tested |
| NULQ-SYS-006 | security_control | — | — | — | Not lab-tested |

## 8. Coverage gaps

| Area | Gap | Severity | Plan |
|------|-----|----------|------|
| internal/engine/store | No dedicated test file | Low | Add store_test.go |
| internal/platform/linux/systemd | No dedicated test file | Low | Add systemd collector test |
| internal/evidence | No dedicated test file | Low | Add evidence builder test |
| internal/platform/linux/acl | Has test | — | — |
| internal/reporting | Has test | — | — |
| Benchmarks | None defined | Medium | Add benchmark tests |
| Fuzzing | None defined | Medium | Add fuzzing for parsers |
| Lab scenarios | No manifest files | High | Create lab manifests |

## Test commands

```bash
gofmt -l .              # formatting check (must be empty)
go vet ./...            # static analysis
go test ./...           # all unit tests
go test -race ./...     # race detector
go test -bench=./...    # benchmarks (none defined yet)
```
