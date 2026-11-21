# 0006 — Schema versioning and output separation

- Status: accepted
- Date: 2026-11-21

## Context

NULQ is consumed by scripts and other tools. Terminal text is a presentation
detail; JSON is the contract. Mixing logs, progress, colour and findings on one
stream breaks every consumer that tries to parse it.

## Decision

- JSON is a first-class interface with a published JSON Schema (draft 2020-12),
  currently version `1.0`.
- Output formats: terminal, JSON, JSONL, Markdown. Each writes only its own
  content to the chosen destination.
- Diagnostics (slog) always go to stderr; machine formats never include ANSI,
  banners or progress output.
- Exit codes are part of the contract: 0 success, 1 runtime failure/incomplete
  scan, 2 usage error, 3 `--fail-on` threshold met.
- Unknown modules/rules/formats are usage errors, not silent narrowing.
- Observations are opt-in for scans to keep default reports small; evidence is
  always included so findings remain auditable.
- Additive, optional fields do not bump the schema; removals or semantic
  changes do, with a changelog entry.

## Consequences

Positive:

- Consumers can stream JSONL and validate JSON without terminal heuristics.
- CI can gate on exit code 3 with a valid report to upload.
- Output size stays manageable while evidence remains complete.

Negative:

- Two representations (terminal and JSON) need separate tests.
- Observations needed for deep review require an explicit flag.
- Schema evolution requires discipline; `additionalProperties: false` at the top
  level may break consumers that add their own fields (documented).

## Alternatives considered

- **Single human format with `--json` flag mixing diagnostics**: rejected; the
  failure mode is well known.
- **Protobuf or MessagePack**: smaller, but harder to inspect and validate for
  the target audience.
- **SARIF as the only machine format**: evaluated for M6; JSON remains the
  primary contract because SARIF cannot express evidence provenance cleanly.
