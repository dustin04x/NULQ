# ADR 0009 — Explicit coverage classification in the report

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

The v1.0 report exposed `scan.partial` and per-root observation counts, but it
could not answer three different questions a consumer must not conflate:

1. Did every collector and rule finish? (`execution_complete`)
2. Was the intended scope actually inspected? (`coverage_complete`)
3. Which checks were impossible in this environment? (unsupported/unavailable)

A successful exit code said nothing about unreadable subtrees, and a rule
skipped because it had no data looked identical to one skipped because data was
missing.

## Decision

Add a required top-level `coverage` object (schema 1.1):

- `status`: `complete`, `partial`, `limited` or `failed`, defined by explicit
  precedence — failure of any collector/rule, then truncation or traversal
  errors, then unsupported environment data, otherwise complete.
- `execution_complete` and `coverage_complete` as independent booleans.
- Aggregate and per-root counts: `files_examined`, `directories_examined`,
  `traversal_errors`, `permission_denied`, `truncated`.
- `unavailable_observations`, `unsupported_observations` and `truncated_roots`.
- `skipped_rules` with the engine's reason string.

The filesystem collector now distinguishes permission-denied traversal failures
from other errors (`scan_denied` attribute) so access limits are not reported as
I/O faults.

A rule skipped because its data category is genuinely empty is recorded but
**does not** downgrade coverage: there was nothing to assess, not a gap. Only
truncation, traversal errors, collector/rule failure and unsupported environment
data affect the verdict.

Schema 1.1 is additive: existing consumers that ignore `coverage` keep working,
and `pkg/api` exposes the same types. The `schema_version` value changes so
consumers can rely on the field's presence.

## Consequences

- Consumers can distinguish "ran clean" from "saw everything".
- Reports are slightly larger; fixture scans with unreadable subtrees now
  declare partial coverage, which is the honest result.
- Status semantics are documented and tested; the lab asserts them per scenario.
- Any future status value requires a schema version bump and an ADR update.

## Alternatives considered

- **Keep `scan.partial` only:** cannot express truncation versus access denial
  versus failed rule.
- **Optional `coverage` object:** would force every consumer to handle absence
  and would let a producer silently omit the honesty data.
- **Bump to schema 2.0:** unnecessary; no field was removed or re-typed.
