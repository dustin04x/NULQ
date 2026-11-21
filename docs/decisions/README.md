# Architecture decision records

ADRs record decisions that are expensive to reverse. Each has a status
(`proposed`, `accepted`, `superseded`), context, decision, consequences and the
alternatives considered.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-observation-first-architecture.md) | Observation-first architecture | Accepted |
| [0002](0002-standard-library-only.md) | Standard library only | Accepted |
| [0003](0003-engine-concurrency-and-isolation.md) | Bounded concurrency with per-rule isolation | Accepted |
| [0004](0004-evidence-provenance-and-stable-ids.md) | Evidence provenance and content-derived IDs | Accepted |
| [0005](0005-read-only-and-least-privilege.md) | Read-only operation and least privilege | Accepted |
| [0006](0006-schema-versioning-and-output-separation.md) | Schema versioning and output separation | Accepted |
| [0007](0007-observation-scope-and-budget.md) | Per-filesystem budgets and default exclusions | Accepted |
| [0008](0008-docker-alpine-laboratory.md) | Docker + Alpine as the reproducible assessment laboratory | Accepted |
| [0009](0009-coverage-classification.md) | Explicit coverage classification in the report | Accepted |

## Template

```markdown
# NNNN — Title

- Status: proposed | accepted | superseded by NNNN
- Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Alternatives considered
```
