# Testing strategy

NULQ is assessed with the same standard it applies to systems: evidence over
assertions. Tests are designed to fail when behaviour regresses, not to
describe implementation details.

## Layers

| Layer | Location | Purpose |
|---|---|---|
| Model invariants | `internal/core/models` | ID stability, validation, ordering, mode formatting |
| Registry | `internal/engine/registry` | Metadata validation, duplicate rejection, selection errors |
| Engine | `internal/engine/executor` | Prerequisites, isolation, panic recovery, timeouts, dedupe |
| Aggregation | `internal/engine/aggregation` | Referential integrity, dedupe, ordering |
| Collectors | `internal/platform/linux/*` | Real `/proc`/`/sys` reads, fixture traversal, symlink semantics |
| Rules | `internal/rules/*` | Positive, negative and unavailable cases |
| Reporting | `internal/reporting` | JSON validity, JSONL envelope, sanitization, Markdown |
| CLI | `internal/cli` | Exit codes, format routing, fixtures, budget behaviour |
| End-to-end | `tests/integration` | Full pipeline against synthetic roots and named scenarios |

## Fixtures

Fixtures are created at test time in `t.TempDir()`:

- set-owner-ID files use `0o755|fs.ModeSetuid`; Go's `FileMode` does not accept
  the raw `0o4000` bit;
- world-writable directories are chmod'ed after creation so the process umask
  cannot mask the bits;
- PATH analysis is isolated by injecting `PathEnv` into `app.ScanConfig` or by
  clearing `PATH` in CLI tests.

No fixture requires root and no test depends on the host's real installed
packages. Root-owned scenarios that cannot be created unprivileged are covered
by synthetic observation sets in rule tests.

## Named scenarios

`tests/integration` implements reproducible scenarios:

| Scenario | Asserts |
|---|---|
| Privileged locations | SUID + world-writable fixture produce one finding each with evidence |
| Safe symlink PATH | `/bin`-style symlink to a non-writable directory produces no FS-003 finding |
| Truncated coverage | File budget exhaustion marks the report partial and adds a limitation |
| API compatibility | CLI-equivalent JSON round-trips through `pkg/api` with evidence intact |
| Deterministic ordering | Two scans of unchanged state yield identical finding order |
| Unknown module | Invalid selection fails loudly |
| Model invariants | Schema version, tool identity, timestamps, limitations |

See `tests/scenarios/README.md` for the scenario catalogue.

## Parser fuzzing

`FuzzUnescapeMountField` exercises the octal-escape decoder used for
`/proc/self/mounts`. It asserts no panic and no expansion beyond input length.
New parsers (sudoers, systemd units, crontabs) must ship with a fuzz target
before being considered complete.

## Race and concurrency

`go test -race ./...` is required in CI. Engine tests exercise concurrent
collectors and rules, panic isolation and timeout cancellation. The observation
store is immutable after construction, which removes shared-write races by
design.

## Running

```bash
go test ./...            # full suite
go test -race ./...      # race detector
go test ./internal/rules/filesystem -run TestSUID -v
go test ./tests/integration -v
go test -fuzz=FuzzUnescapeMountField ./internal/platform/linux/filesystem
```

## What is deliberately not tested

- Exploitation outcomes: NULQ makes no exploitation claims, so none are tested.
- Root-only host paths: privileged integration tests are planned for M7 as an
  opt-in target with an isolated fixture tree.
- Real distribution diversity: the CI matrix builds both architectures, but
  collector behaviour is validated against the runner's Linux only. Additional
  distributions belong in M4.

## Quality gates

Before a change is complete: `gofmt -l .` empty, `go vet ./...`,
`go test ./...`, `go test -race ./...`, `make build`, and a cross-compile for
linux/arm64. Release gates additionally include `make release`, `make verify`
and a real scan whose JSON is checked for dangling evidence and coverage.
