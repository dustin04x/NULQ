# Phase Eight: Determinism and Reproducibility

**Recorded:** 2026-11-22T09:47:00Z  

## Determinism verification

### Lab (static fixtures) — fully deterministic

Two consecutive `make lab-test` runs produced identical results:

| Run | Supported | Unsupported | Missing | Unexpected | Invalid scans |
|-----|-----------|-------------|---------|------------|---------------|
| 1 | 34/34 | 5 | 0 | 0 | 0 |
| 2 | 34/34 | 5 | 0 | 0 | 0 |

All 5 schema validations passed in both runs. Lab scenario verdicts are
deterministic because fixtures are static and the binary is deterministic.

### Live host scan — point-in-time variance expected

Two consecutive `nulq scan --format json` runs:

| Metric | Scan 1 | Scan 2 | Difference |
|--------|--------|--------|------------|
| Findings | 1006 | 1007 | +1 dynamic process |
| Files examined | 507493 | 507494 | +1 |
| Directories examined | 51716 | 51716 | 0 |
| Traversal errors | 49 | 49 | 0 |
| Permission denied | 49 | 49 | 0 |
| Unavailable observations | 40 | 41 | +1 |

The single difference is NULQ-SYS-003 observing one additional process
(`/proc/67585`) that appeared between scans. This is expected: process state
is dynamic. The code itself is deterministic — same input observations produce
same output. Observation IDs are content-derived (SHA-256 over kind+resource),
so the same system state yields identical IDs across runs.

## Reproducibility

- `go build` produces identical binary (same source, same flags)
- `make lab-test` produces identical scenario verdicts across runs
- Observation IDs are stable across runs (content-derived, not time-based)
- Report IDs differ per run (expected — they include scan timestamps)

## No determinism defects found

The only variance is from live system state (processes), not from code
nondeterminism. Lab results are fully reproducible.
