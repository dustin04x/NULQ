# 0001 — Observation-first architecture

- Status: accepted
- Date: 2026-11-21

## Context

Linux assessment tools commonly consist of independent checks that each call
`stat`, read `/proc`, or shell out to utilities. The approach is simple to start
and pathological to maintain: duplicated collection, inconsistent error
handling, and findings that cannot be traced to a specific fact.

NULQ's defining requirement is that a reviewer can reconstruct why a finding
exists from the report alone.

## Decision

Split the system into a collection phase that publishes normalized, immutable
observations, and a detection phase that consumes a shared observation set.
Collectors never judge; rules never collect.

- Observation kinds and attribute encodings are documented contracts.
- The store deduplicates, sorts and freezes observations before rules run.
- Rules declare the observation kinds they require.
- Findings cite observation IDs and fields through evidence.

## Consequences

Positive:

- One traversal and one `/proc` read serve every rule.
- Rules are pure functions, cheap to test and safe to run concurrently.
- Missing or unreadable data is represented once, consistently.
- Evidence provenance is structural, not aspirational.

Negative:

- New checks sometimes require a new collector kind rather than a local read.
- The observation vocabulary needs governance and schema updates.
- Very specific one-off checks may be awkward inside the model.

## Alternatives considered

1. **Independent rules with direct system access.** Fast to add checks; makes
   provenance and shared error semantics impossible. Rejected.
2. **A generic key/value fact bag.** Easier to extend, but loses typed kinds and
   allows rules to depend on undocumented keys. Rejected in favour of a closed
   kind vocabulary with documented attributes.
3. **Persist observations to a database.** Adds operational weight with no
   benefit for a single-scan CLI. Rejected; in-memory immutability is enough.
