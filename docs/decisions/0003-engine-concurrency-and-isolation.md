# 0003 — Bounded concurrency with per-rule isolation

- Status: accepted
- Date: 2026-11-21

## Context

Assessment runs on systems that may be slow, hostile or partially unreadable.
Collectors can block on I/O; rules can contain bugs; a single hang or panic
must not destroy the entire assessment. At the same time, running every rule
sequentially wastes time when the observation set is already in memory.

## Decision

A single executor owns orchestration:

- One semaphore bounds collectors and rules (`--concurrency`).
- Collectors and rules receive context-derived deadlines.
- Each rule evaluation is wrapped with panic recovery.
- A rule error, panic or timeout marks only that rule failed.
- Invalid rule output (missing evidence, dangling references, wrong rule ID)
  discards that rule's output.
- Findings are merged only after all rules finish, with referential-integrity
  checks, deduplication and deterministic ordering.
- Cancellation is checked before acquiring a slot, before evaluation, between
  rule iterations and inside traversal loops.

## Consequences

Positive:

- A faulty rule cannot corrupt or abort a scan.
- Time and memory use are bounded and observable.
- Reports distinguish executed, skipped and failed rules.

Negative:

- Panic recovery hides programming errors at runtime; therefore panics are
  logged at warn level and turn the report partial, and tests cover the path.
- Partial output from a failed rule is discarded, which can hide useful data.
  This is deliberate: unreviewed output must not reach a security report.
- Per-rule timeouts require rules to honour context; the engine detects ignored
  cancellation after the fact and fails the rule.

## Alternatives considered

1. **Sequential execution.** Simplest, but collector and rule latency add up and
   a hang blocks everything.
2. **Unbounded goroutines.** Faster in theory, but violates the resource limits
   required for constrained environments.
3. **Let a failing rule abort the scan.** Unacceptable for an assessment tool;
   operators need the rest of the results.
