# Contributing to NULQ

## Before you start

Read `MISSION.md`, `AGENTS.md` and `docs/architecture.md`. The project values
correct, evidence-backed analysis over feature count. A rule that produces one
defensible finding is preferable to ten heuristics.

## Development setup

Requirements: Go 1.24+, Linux. No external services or dependencies.

```bash
make build
make test
make race
make lint
```

`make lint` runs `gofmt` verification, `go vet`, and `staticcheck` when it is
installed. CI runs the same checks plus cross-compilation for linux/amd64 and
linux/arm64.

## What makes a good change

1. **It fixes a cause, not a symptom.** If a PATH symlink caused a false
   positive, fix the permission semantics and add a regression test.
2. **It preserves the layering.** Collectors normalise, rules interpret,
   renderers present. Rules do not read files.
3. **It states its limitations.** Every finding carries a Limitations section;
   documentation carries a limitations section.
4. **It is tested at the right level.** Unit tests for rules and parsers;
   fixture integration tests for end-to-end behaviour; no root required.
5. **It does not silently narrow or widen a scan.** Unknown modules and rules
   are usage errors; missing data is a skipped rule, never an assumed result.

## Adding a rule

See `docs/rule-development.md`. Required: metadata, precise observation
prerequisites, evidence for every claim, positive and negative table tests,
an unavailable-data case, explicit registration, and a changelog entry.

## Style

- Go standard formatting; no generated code.
- Errors carry a class from `internal/core/errors`.
- IDs are content-derived via the helpers in `internal/core/models`.
- Never add a dependency without an ADR in `docs/decisions/`.
- Comments explain *why* a decision is safe; avoid narrating code.
- Do not use `init()` for registration or side effects.

## Commits

Use imperative, scoped subjects, for example:

```text
filesystem: resolve PATH entries through symlinks

The symlink's own 0777 mode was treated as directory permissions, which
reported /bin as writable. Evaluate the target with Stat and record the link.
```

One logical change per commit. Do not mix formatting-only changes with
behaviour changes.

## Reporting defects

For defects in NULQ's own security posture, follow `SECURITY.md`. For detection
false positives or false negatives, include the observation attributes and the
rule ID; those are the minimum needed to reproduce the reasoning.
