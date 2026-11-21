# M4 Risk Register

**NULQ — M4 architecture & engineering blueprint**

This document records risks for M4 workstreams, their likelihood, impact, mitigation,
and owner. It does not implement any M4 code.

**Gate note:** M3.5 was not completed. Risks R1 and R2 are elevated because M4.1/M4.2
depend on unverified M3.5 foundations.

## Risk register

| ID | Risk | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|---|
| R1 | M3.5 foundations unverified: correlation engine / evidence integrity may be rejected | High | High | M4.1/M4.2 gated behind M4.0 go/no-go; M4.3/M4.4/M4.5 independent | Open |
| R2 | Entity ID stability vs. observation-attribute evolution: IDs change if attributes change | Medium | Medium | Document IDs as observation-content-dependent, not system-state-stable | Open |
| R3 | Correlation false positives: severity promoted on low-confidence constituents | Medium | High | Severity cap (highest confirmed constituent); confidence weakest-link; boundary tests | Open (blocked on M3.5) |
| R4 | Deterministic serialization scope creep: wall-clock fields leak into "deterministic" output | Low | Medium | Explicit exclusion list; byte-identical test on identical fixtures | Open |
| R5 | New rules label inventory as vulnerability: presence mistaken for exposure | Low | Medium | Conservative default severity (INFO/LOW/MEDIUM); limitations written per rule | Open |
| R6 | Mount context collection exceeds read-only scope: traversal beyond assigned path | Low | Medium | Collector scope enforcement; read-only bind mounts only | Open |
| R7 | Policy file accepts code execution or path traversal | Low | High | Data-only policy; reject invalid rule IDs and `../` paths; validation tests | Open |
| R8 | Relationship graph self-loops or dangling endpoints corrupt aggregation | Low | High | Graph validation rejects dangling refs and self-loops; referential integrity in aggregation | Open (blocked on M3.5) |
| R9 | CI smoke-test path defect (`./bin/nulq` vs `/tmp/nulq-amd64`) masks M4 build regressions | Medium | High | Fix CI path separately (out of M4 scope, documented); do not rely on CI smoke test | Known |
| R10 | Standard-library-only constraint limits parser richness (mountinfo, sysctl) | Medium | Low | Content-derived parsers in stdlib; fuzz testing for malformed input | Open |

## Top risks detail

### R1 — M3.5 foundations unverified
M4.1 (entity/relationship) and M4.2 (correlation findings) assume the M3.5 relationship
model and evidence integrity are sound. If M3.5 rejects them, M4.1/M4.2 must be
redesigned before implementation.

**Mitigation:** M4.0 records a go/no-go decision. M4.1/M4.2 do not start until M3.5 is
accepted. M4.3/M4.4/M4.5 proceed regardless.

**Trigger:** M4.0 go/no-go decision.

### R3 — Correlation false positives
Correlation aggregates multiple observations into findings. Without a severity cap,
low-confidence constituents could combine to imply HIGH severity.

**Mitigation:** Correlated finding severity = max of constituents, capped by highest
`EvaluationConfirmed` constituent. Confidence = weakest-link min. HIGH requires
`EvaluationConfirmed`. Boundary tests at INFO/LOW/MEDIUM/HIGH.

**Trigger:** M4.2 integration tests; severity boundary test suite.

### R5 — New rules label inventory as vulnerability
A SUID binary or root-owned file is inventory, not necessarily exposure. New rules must
not escalate on presence alone.

**Mitigation:** New rules default to INFO/LOW/MEDIUM only. Each rule documents
false-positive considerations. No HIGH/CRITICAL for new M4 rules.

**Trigger:** M4.3 rule reviews; negative-control test fixtures.

### R7 — Policy file safety
A detection policy file could be crafted to execute code or traverse paths if the
parser is lenient.

**Mitigation:** Policy is data-only (rule selection + severity override). No script/eval.
Invalid rule IDs rejected. Path traversal (`../`) rejected.

**Trigger:** M4.5 policy validation tests; adversarial input tests.

### R9 — CI smoke-test path defect (known)
`.github/workflows/ci.yml` cross-compiles to `/tmp/nulq-amd64` but smoke-test runs
`./bin/nulq` (nonexistent). This masks build regressions in CI.

**Mitigation:** Documented as a known defect; out of M4 documentation scope. M4 does
not modify CI. Local cross-compile verification required instead.

**Trigger:** CI run; known defect recorded in blueprint.

## Risks closed or deferred (none yet)

No M4 risks are closed at this stage. All are open pending implementation.

## Risk review cadence

Reviewed at each stage exit criteria. R1 re-evaluated at M4.0 go/no-go. R3/R8 re-evaluated
when M4.1/M4.2 unblock.
