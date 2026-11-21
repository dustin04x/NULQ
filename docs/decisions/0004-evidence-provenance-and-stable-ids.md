# 0004 — Evidence provenance and content-derived IDs

- Status: accepted
- Date: 2026-11-21

## Context

Two requirements conflict with conventional tooling:

1. Findings must be independently understandable and traceable to source facts.
2. Reports must be reproducible and diffable across scans.

Random UUIDs or timestamp-based identifiers make (2) impossible. Evidence that
exists only as prose makes (1) impossible.

## Decision

- Observations, evidence and findings carry content-derived IDs:
  `obs-<kind-slug>-<12 hex>`, `ev-<12 hex>`, `fnd-<12 hex>`.
- IDs hash canonical content only: kind + resource; observation ID + field;
  rule ID + resource + stable title. Timestamps and collectors are excluded.
- Findings reference evidence by ID; evidence references an observation ID and
  field; observations carry collector and collection time.
- The engine enforces that every finding cites evidence that the same rule
  returned, and aggregation rejects dangling references.
- Titles are stable; dynamic values belong in Explanation or Resource.

## Consequences

Positive:

- Re-scans of unchanged state produce identical IDs and ordering, enabling diffs
  and baseline suppression later.
- A reviewer can walk finding → evidence → observation → collector → time.
- Duplicate evidence collapses automatically.

Negative:

- Hashed IDs are opaque in raw logs; the report includes resources and fields to
  compensate.
- Renaming a rule's title or resource changes finding IDs and breaks baselines;
  this is treated as a rule-version change.
- Content-derived IDs do not distinguish two observations of the same resource
  at different times; NULQ is a point-in-time scanner, so this is acceptable.

## Alternatives considered

- **Sequential IDs:** unstable under concurrency and selection changes.
- **UUIDv4:** not reproducible; diffs become noise.
- **Embedding full evidence text in findings:** produces duplication and makes
  cross-referencing impossible.
