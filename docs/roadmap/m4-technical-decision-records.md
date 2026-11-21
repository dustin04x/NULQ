# M4 Technical Decision Records

**NULQ — M4 architecture & engineering blueprint**

This document records M4 technical decisions, their context, alternatives considered,
and consequences. It does not implement any M4 code.

**Gate note:** M3.5 was not completed. Decisions D4 and D5 depend on M3.5 acceptance.

---

## D1 — Entity and relationship packages are additive and internal (not emitted)

**Context:** NULQ has no stable resource identity or validated relationship model.
M4.1 needs entity IDs and a relationship graph for correlation, but the report schema
(v1.1) must remain unchanged.

**Decision:** Create `internal/core/entity` and `internal/core/relationship` as new
packages. Entities and relationships are internal to the engine; they are NOT emitted
in the default report. Emission is a separate M4.4/schema decision.

**Alternatives considered:**
- Emit entities/relationships in the report with schema v1.2: rejected; schema change
  is out of M4 scope and requires consumer impact analysis.
- Extend existing observation kinds with relationship fields: rejected; observations
  are closed-vocabulary and relationship semantics belong in a dedicated graph.

**Consequences:**
- Additive only; no existing package modified.
- Entities/relationships invisible to report consumers unless a future schema version
  exposes them.
- Correlation consumes them internally (M4.2).

**Status:** Proposed (M4.1).

---

## D2 — Correlated findings use scenario ID as RuleID (COR-<NNN>)

**Context:** Correlation engine produces findings but is not one of the 8 registered
detection rules. The finding model requires a `RuleID`.

**Decision:** Correlated findings set `RuleID` to the correlation scenario ID
(e.g., `COR-001`) with `RuleVersion` = correlation engine version. This is a documented
exception to the "RuleID must be a registered detection rule" convention.

**Alternatives considered:**
- Register COR scenarios as detection rules in `internal/rules/rules.go`: rejected;
  correlation is engine infrastructure, not a detection rule with `Required` kinds.
- Use a synthetic rule ID like `CORRELATION-ENGINE`: rejected; scenario IDs are more
  traceable and content-derived.

**Consequences:**
- Finding consumers must tolerate `RuleID` values outside the registered rule set.
- Documented limitation: correlated findings are not re-evaluated by detection rules.

**Status:** Proposed (M4.2, blocked on M3.5).

---

## D3 — Deterministic serialization excludes DetectedAt and wall-clock fields

**Context:** Identical input should produce byte-identical JSON for reproducibility.
`DetectedAt` and scan start/finish times are wall-clock and vary per scan.

**Decision:** Deterministic-report mode normalizes `DetectedAt` to the scan start time
(or omits it) and normalizes the report ID. Default mode preserves wall-clock values.
The determinism guarantee is documented, not default.

**Alternatives considered:**
- Remove `DetectedAt` entirely: rejected; it is useful provenance and part of schema
  v1.1.
- Make all timestamps deterministic including scan start/finish: rejected; those are
  genuinely dynamic and useful for operations.

**Consequences:**
- `--deterministic` flag required for byte-identical output.
- Default scans remain non-deterministic (documented).
- Schema v1.1 unchanged.

**Status:** Proposed (M4.4).

---

## D4 — Correlated finding severity capped by highest confirmed constituent

**Context:** Aggregating multiple observations could imply higher severity than any
single constituent justifies, especially with low-confidence data.

**Decision:** Correlated finding severity = `max(constituent severities)`, capped by the
highest `EvaluationConfirmed` constituent. `EvaluationPotential` caps at MEDIUM;
`EvaluationInsufficient`/`EvaluationUnknown` cap at INFO/LOW. Confidence = weakest-link
min (never increased by accumulation).

**Alternatives considered:**
- Uncapped max severity: rejected; risk of false-positive HIGH/CRITICAL findings.
- Sum/average of confidences: rejected; confidence is not additive.

**Consequences:**
- HIGH/CRITICAL correlated findings require `EvaluationConfirmed` evidence.
- Boundary tests required at each severity level.

**Status:** Proposed (M4.2, blocked on M3.5).

---

## D5 — New M4 rules never exceed MEDIUM severity

**Context:** New hardening rules (capabilities, seccomp, systemd, userns) detect
configuration states that are not themselves exploits.

**Decision:** All new M4 rules default to INFO/LOW/MEDIUM only. No new rule produces
HIGH or CRITICAL. Presence of a capability or missing hardening directive is advisory,
not demonstrated exposure.

**Alternatives considered:**
- Allow HIGH for root + capability combinations: rejected; that is correlation
  territory (M4.2), not a single-rule determination.

**Consequences:**
- New rules are conservative; false-positive risk minimized at the cost of some
  true-positive sensitivity.
- HIGH/CRITICAL findings remain the domain of existing rules (NULQ-FS-001/002) and
  future correlation.

**Status:** Proposed (M4.3).

---

## D6 — Mount context is additive to existing observation kinds

**Context:** Bind source, propagation, and effective mount flags are useful for SUID
and world-writable directory analysis, but existing observation kinds are closed.

**Decision:** Mount context is recorded as additional attributes on existing
`filesystem.file`/`filesystem.directory` observations (additive), not as new observation
kinds.

**Alternatives considered:**
- New `filesystem.mount` observation kind: rejected; mounts are already observed via
  `filesystem.mount` in existing collectors; context should enrich existing records.
- Separate mount report section: rejected; out of M4 scope and schema change.

**Consequences:**
- Existing observation kinds gain optional mount attributes; consumers tolerate unknown
  attributes (already supported by the model).
- No schema change.

**Status:** Proposed (M4.4).

---

## D7 — Policy is data-only; no code execution

**Context:** Operators need to select rules and override severity without modifying Go
code. A policy file could be a vector for code execution if the parser is expressive.

**Decision:** Policy file supports rule selection (include/exclude by ID) and severity
override only. No script, eval, templating, or code execution. Invalid rule IDs and
path traversal (`../`) are rejected at load.

**Alternatives considered:**
- Rego/OPA or embedded Lua: rejected; violates standard-library-only and introduces
  execution risk.
- Go code overrides: rejected; requires recompilation and is not operator-friendly.

**Consequences:**
- Policy cannot express complex conditions (e.g., "only if user is root AND on prod").
- Complex policy is deferred to a future version.

**Status:** Proposed (M4.5).

---

## D8 — M4 remains standard-library-only

**Context:** NULQ's invariant (ADR in `docs/decisions/`) is standard library only unless
an ADR justifies a dependency.

**Decision:** No new dependencies for M4. Mountinfo parsing, sysctl parsing, policy
parsing (YAML/JSON via stdlib `encoding/json`; YAML deferred or hand-parsed), and
hashing all use the standard library.

**Alternatives considered:**
- `github.com/hashicorp/hcl` or `gopkg.in/yaml.v3`: rejected; would require an ADR
  and is unnecessary for M4 scope.

**Consequences:**
- YAML policy (if chosen) requires a hand-written minimal parser or JSON-only policy.
- All M4 code passes `go vet` with no external deps.

**Status:** Proposed (applies to all stages).

---

## Decision log format

Each future M4 decision follows this format:

```
## D<N> — <Title>

**Context:** <why the decision is needed>
**Decision:** <what was decided>
**Alternatives considered:** <options rejected and why>
**Consequences:** <positive and negative outcomes>
**Status:** Proposed / Accepted / Rejected / Superseded
**Stage:** M4.x
```

Decisions are recorded in `CHANGELOG.md` when accepted. Superseded decisions are
annotated, not deleted.
