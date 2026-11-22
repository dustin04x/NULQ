# CLI Contract Report — NULQ

This report documents NULQ's command-line interface contract: commands,
flags, exit codes, output formats, and their verification status.

## 1. Commands

| Command | Description | Status | Test |
|---------|-------------|--------|------|
| `nulq <cmd> -h` / `--help` | Show usage | Pass | cli_test.go:TestUsageErrors |
| `nulq version` | Print build metadata | Pass | cli_test.go:TestVersionCommand |
| `nulq version --format json` | JSON version output | Pass | cli_test.go:TestVersionCommand |
| `nulq scan [flags]` | Run assessment | Pass | cli_test.go (multiple) |
| `nulq system info` | Show collected system facts | — | Manual smoke |
| `nulq rules list` | List registered detection rules | Pass | cli_test.go:TestRulesListCommand |
| `nulq rules list --format json` | JSON rules list | Pass | cli_test.go:TestRulesListCommand |
| `nulq rules list --module <mod>` | Filter by module | — | Usage error tested |

## 2. Exit codes

| Code | Meaning | Contract | Test |
|------|---------|----------|------|
| 0 | Success | Command completed, no failure threshold met | Pass |
| 1 | Runtime error | Scan or render failed | — |
| 2 | Usage error | Invalid invocation, unknown flag, bad argument | Pass |
| 3 | Findings at/above threshold | `--fail-on` severity met | Pass |

## 3. Scan flags

| Flag | Type | Default | Description | Test |
|------|------|---------|-------------|------|
| `--format` | string | "terminal" | terminal, json, jsonl, markdown | Pass |
| `--output` | string | "" | Write report to file ("-" for stdout) | — |
| `--modules` | string | "" | Comma-separated modules | Pass (invalid module tested) |
| `--rules` | string | "" | Comma-separated rule IDs | Pass (unknown rule tested) |
| `--root` | string | (repeatable) | Restrict filesystem discovery | Pass |
| `--max-files` | int | 1000000 | Maximum entries per root | Pass (budget test) |
| `--concurrency` | int | NumCPU | Max concurrent collectors/rules | — |
| `--rule-timeout` | duration | 20s | Per-rule timeout | Pass (executor test) |
| `--collector-timeout` | duration | 2m | Per-collector timeout | — |
| `--timeout` | duration | 5m | Overall scan timeout | — |
| `--observations` | bool | false | Include observations in report | — |
| `--deterministic` | bool | false | Normalize timestamps | Pass (manual) |
| `--fail-on` | string | "" | Exit 3 at/above severity | Pass |
| `--color` | string | "auto" | auto, always, never | — |
| `--quiet` | bool | false | Suppress INFO/LOW findings | Pass |
| `--verbose` | bool | false | Debug logging | — |

## 4. Output formats

| Format | Content | Sterile stdout | Test |
|--------|---------|----------------|------|
| JSON | Full report object | Yes | Pass |
| JSONL | One object per line (scan, finding, evidence, observation, summary) | Yes | Pass |
| Markdown | Human-readable report with findings table | Yes | Pass |
| Terminal | Colorized human output (ANSI only on TTY) | Yes | Pass |

**Sterility guarantee**: No ANSI, banners, or log records on stdout in JSON,
JSONL, or Markdown modes. Logs go to stderr only.

## 5. Output file permissions

Report files are created with mode 0600 (`os.O_CREATE|O_WRONLY|O_TRUNC,
0o600`). Reports are treated as sensitive.

## 6. Color behavior

- `always`: ANSI enabled
- `never`: ANSI disabled
- `auto`: ANSI only if destination is a character device and NO_COLOR is unset

## 7. Verification status

| Contract element | Verified | Method |
|------------------|----------|--------|
| 12 rules registered | Yes | cli_test.go:TestRulesListCommand |
| Exit codes 0/1/2/3 | Yes (0, 2, 3) | cli_test.go; 1 not directly tested |
| JSON schema v1.1 | Yes | Manual validation against schema |
| Deterministic output | Yes | `--deterministic` byte-identical on fixture |
| Referential integrity | Yes | cli_test.go:TestScanFixtureProducesConsumableJSON |
| Fail-on contract | Yes | cli_test.go:TestScanFailOnContractCoverages |
| No findings exit 0 | Yes | cli_test.go:TestScanFailOnNoFindings |
| Usage error handling | Yes | cli_test.go:TestUsageErrors |
| Unknown rule rejection | Yes | cli_test.go:TestScanRejectsUnknownRule |
| Output file 0600 | Yes | flags.go:openOutput |
| Sanitization (no escapes) | Yes | reporting_test.go |

## 8. Gaps

| Gap | Impact | Plan |
|-----|--------|------|
| Exit code 1 not directly tested | Runtime error path untested at CLI level | Add test for scan failure |
| `--output` file flag not tested | File output path untested | Add CLI integration test |
| `--color always/never` not tested | Color mode selection untested | Add terminal renderer test |
| `--module` filter for rules list not tested | Module filtering untested | Add rules list test |
| `--concurrency` not tested | Concurrency flag untested at CLI level | Add executor test via CLI |
