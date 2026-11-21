# M4 Final Scope

**NULQ — Final M4 scope after red-team review**

This document defines what M4 will and will not deliver, based on the adversarial
review in `m4-red-team-review.md` and the corrections in
`m4-design-corrections.md`. M3.5 acceptance is a hard prerequisite for M4.1 and M4.2.

---

## M3.5 gate status

**M3.5 acceptance is absent.** No `docs/audits/m35-*` documents exist. M4 cannot
issue a "go" decision until M3.5 is completed, documented, and accepted.

**Consequence:** M4.1 (entity model + relationship graph) and M4.2 (correlation
findings + aggregation) are **deferred**. They cannot be implemented, tested, or
accepted without M3.5.

---

## M4 stages — final disposition

| Stage | Title | Disposition | Reason |
|-------|-------|-------------|--------|
| M4.0 | Foundations gate | **CONDITIONAL** | Cannot issue "go" without M3.5 verdict |
| M4.1 | Entity model + relationship graph | **DEFERRED** | Blocked on M3.5 acceptance |
| M4.2 | Correlation findings + aggregation | **DEFERRED** | Blocked on M3.5 acceptance |
| M4.3 | New detection rules (capabilities, seccomp, systemd) | **IN SCOPE** (3 of 4) | Implementable now; NULQ-SYS-006 removed |
| M4.4 | Deterministic serialization + mount context | **IN SCOPE** (deterministic only) | Mount-context extension has no attribute contract; deferred |
| M4.5 | Detection policy overrides | **DEFERRED** | Zero interface design; not implementation-ready |

---

## M4.3 — Detection rules in scope

### Included rules

**NULQ-SYS-003 — Privileged process capabilities**
- Kind: `process.info`
- Checks: root euid + CapEff contains privilege-bypassing capability
- Severity: MEDIUM (root), INFO (non-root)
- Fix DC-8: `Required` changed from `process.info, identity.execution_context` to `process.info`

**NULQ-SYS-004 — Seccomp disabled on root process**
- Kind: `process.info`
- Checks: root euid + Seccomp mode 0
- Severity: INFO
- Note: narrow scope; limited detection value but technically correct

**NULQ-SYS-005 — Systemd unit lacking hardening**
- Kind: `KindSystemdUnit` (new)
- Checks: unit runs as root without NoNewPrivileges
- Severity: LOW
- Note: fix DC-10 — lab-testability unverified; lab container has no systemd

### Removed rules

**NULQ-SYS-006 — Unprivileged user namespaces** — REMOVED
- Duplicate of NULQ-SYS-001 (same `kernel.unprivileged_userns_clone` check)
- Fix DC-7

### Rule count change
- Original blueprint: 4 new rules (NULQ-SYS-003..006)
- Final scope: 3 new rules (NULQ-SYS-003..005)
- Total registered rules: 11 (8 existing + 3 new)

---

## M4.4 — Deterministic serialization in scope

### Included

**`--deterministic` flag** on `nulq scan`
- Normalizes `DetectedAt` to a sentinel (fix DC-11 — omit or use well-known sentinel,
  not `time.Time{}` year-1)
- Deterministic report ID from hostname only
- Fixes CI smoke-test path defect (fix DC-4)

### Deferred

**Mount-context extension** — no attribute contract defined (fix DC-15). No rule
consumes mount-context attributes. Deferred until attributes and consumer rule are
specified.

---

## M4.5 — Detection policy deferred

`internal/detection/policy` has zero interface design (fix DC-14). Not implemented
in M4. Deferred to M5 or later.

---

## M4.1/M4.2 — Correlation deferred

Entity model, relationship graph, correlation findings, and aggregation merge of
correlation findings are all blocked on M3.5 acceptance. No M4 code for these
stages should be committed until M3.5 is accepted.

Existing uncommitted correlation engine code (`internal/engine/correlation/`) must
be either committed as part of an accepted M3.5 milestone or reverted (fix DC-2).

---

## Code state requirements

Before M4 acceptance, the working tree must satisfy:

1. **All uncommitted M4 implementation code committed or reverted** (fix DC-2)
   - Commit: NULQ-SYS-003, NULQ-SYS-004, NULQ-SYS-005 rules + systemd collector +
     `--deterministic` flag + attribute/observation kind additions
   - Revert: correlation engine, `EvaluationOutcome` duplication, executor wiring,
     correlation test

2. **`EvaluationOutcome` de-duplicated** (fix DC-3) — keep committed version in
   `severity.go`, remove from correlation engine

3. **CI smoke-test path fixed** (fix DC-4) — `./bin/nulq` → `/tmp/nulq-amd64`

4. **NULQ-SYS-006 removed** from spec, `rules.go`, and `userns.go` (fix DC-7)

5. **NULQ-SYS-003 Required fixed** (fix DC-8)

6. **Deterministic timestamp fixed** (fix DC-11) — omit or sentinel, not year-1

7. **Entity/relationship emission contradiction resolved** (fix DC-12)

8. **Schema compatibility verified** (fix DC-13)

9. **M4 acceptance criteria defined** (fix DC-16)

---

## What M4 will NOT deliver

- Entity model or relationship graph (M4.1 — deferred to post-M3.5)
- Correlation findings or aggregation merge (M4.2 — deferred to post-M3.5)
- NULQ-SYS-006 rule (removed — duplicate of NULQ-SYS-001)
- Detection policy overrides (M4.5 — no interface design)
- Mount-context filesystem attributes (M4.4 — no attribute contract)
- Any code that modifies the assessed system (NULQ invariant 1 — read-only only)

---

## Acceptance criteria

M4 is accepted when all of the following hold:

1. M3.5 acceptance document exists and M4.0 "go" decision is recorded
2. Working tree matches committed state (no uncommitted M4 implementation code)
3. `gofmt -l .` empty, `go vet ./...` clean, `go test ./...` passes,
   `go test -race ./...` passes
4. `make build` succeeds; `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq`
   succeeds
5. CI smoke-test path fixed and CI passes
6. NULQ-SYS-003, NULQ-SYS-004, NULQ-SYS-005 each have positive, negative, and
   unavailable-data tests
7. NULQ-SYS-006 removed from all spec and code locations
8. `--deterministic` flag produces deterministic report output (same input → same
   report ID)
9. M4 acceptance criteria documented in `m4-implementation-plan.md`

---

## Exit decision

M4 enters scope only after M3.5 acceptance. Until then, M4.0 holds a conditional
status: foundational work (M4.3 deterministic serialization, 3 detection rules) can
proceed, but M4.1/M4.2/M4.5 are deferred.
