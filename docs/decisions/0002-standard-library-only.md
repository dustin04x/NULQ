# 0002 — Standard library only

- Status: accepted
- Date: 2026-11-21

## Context

NULQ is a security tool that must be auditable and deployable as a single
binary in constrained environments. Every dependency is a supply-chain surface
and a portability constraint. The project constitution requires an engineering
justification for each external dependency.

## Decision

Use the Go standard library exclusively in v0.1.0, including:

- `flag` for CLI parsing;
- `encoding/json` for reports;
- `log/slog` for diagnostics;
- `path/filepath`, `io/fs`, `os` for filesystem work;
- `crypto/sha256` for stable identifiers.

CGO is disabled for release builds (`CGO_ENABLED=0`), producing static
binaries. `os/user` therefore uses its pure-Go `/etc/passwd` and `/etc/group`
fallback rather than NSS; lookups that cannot resolve fall back to numeric
identifiers.

## Consequences

Positive:

- No dependency review, no transitive CVEs, no version conflicts.
- Trivial cross-compilation for amd64 and arm64.
- Operators can build from source in an offline environment.

Negative:

- CLI ergonomics are hand-written; richer shells/flags are unavailable.
- No third-party schema validator in tests or CI.
- NSS-backed user/group resolution is not used for static builds.
- JSON Schema validation by consumers requires their own validator.

## Alternatives considered

- **Cobra/pflag** for CLI structure: convenience not worth the dependency at
  this size. `flag` plus explicit command dispatch is clear.
- **`golang.org/x/sys/unix`** for richer syscalls: `syscall` covers what v0.1.0
  needs (uname, stat ownership). Revisit when capability or namespace work
  requires convenience wrappers.
- **a JSON Schema library** for test-time validation: structural tests plus a
  published schema are sufficient for now; CI validates shape and referential
  integrity directly.

Any future dependency must arrive with an ADR explaining why the standard
library is insufficient and what the supply-chain cost is.
