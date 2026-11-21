# M4 Candidate Workstreams

**NULQ — M4 architecture & engineering blueprint**

This document defines and ranks candidate M4 workstreams developed from the gaps in
`m4-capability-inventory.md`. Candidates are ordered by security value, architectural
fit, implementation effort, evidence quality, false-positive risk, and maintainability.
Each candidate includes a technical definition, architecture, security semantics,
engineering assessment, and acceptance criteria.

**Gate note:** M3.5 was not completed. Workstreams that depend on the relationship
model, evidence integrity, or correlation engine are marked as blocked on M3.5
acceptance and must not be implemented on the unverified foundation.

---

## Candidate 1 — Entity model and validated relationship graph (blocked on M3.5)

**Problem statement:** NULQ has no explicit `Entity` type. The untracked correlation
engine derives `EntityID` ad-hoc from observation fields (inode, UID, mount ID), often
produces empty entity IDs, creates self-referential edges, misuses `PATH_RESOLVES_TO`
for process pairs, and performs no endpoint validation, deduplication, cycle handling,
or bounded traversal. Relationships cannot be trusted as analysis input.

**Security objective:** Give every relationship explicit, validated endpoints and stable
entity identity so correlation reasoning is sound and reproducible.

**Intended user:** Detection engineers and correlation rule authors who need to reason
over objects (files, directories, mounts, processes, identities) rather than raw
observations.

**Concrete use cases:**
- "Process P executes executable X whose parent directory D is writable by identity I."
- "Executable X is mounted on mount M with nosuid."
- "Identities I1 and I2 share executable X."

**Expected output:** An entity registry, entity IDs stable across scans, validated
relationships (source/target exist, no dangling references), deduplicated edges, cycle
detection, bounded graph traversal.

### Architecture
- New package `internal/core/entity` — `Entity`, `EntityID`, entity registry keyed by
  content-derived ID; observations are indexed into entities.
- New package `internal/core/relationship` — `Relationship`, `RelationshipType`,
  `RelationshipGraph` with `Add`, `Validate`, `Dedupe`, `Cycles`, `Traverse` bounded by
  max depth/fan-out.
- Collectors unchanged; a normalizer converts observations to entities/relationships
  after collection, before rules/correlation.
- Errors: dangling endpoint → validation error reported, not silently dropped.

### Security semantics
- Observation → fact about a resource.
- Entity → stable identity of a resource across observations.
- Relationship → explicit semantic edge between two entities, backed by evidence.
- Exposure → a relationship that could cross a privilege boundary (not confirmed).
- Confirmed weakness → relationship + evidence sufficient for the security conclusion.
- UNKNOWN → endpoint or evidence missing; never inferred as allowed.

### Engineering assessment
- Complexity: medium.
- Dependencies: `internal/core/models`, `internal/core/errors`, `internal/engine/store`.
- Performance cost: one normalization pass over observations; linear in observation count.
- Testing: unit tests for entity ID stability, relationship validation, dedup, cycles,
  bounded traversal; property tests for deterministic graph construction.
- Backward compatibility: new packages, no change to existing observation/finding
  contracts.
- Security risks: none (read-only normalization).
- False-positive risk: low (validation rejects, never infers).
- Maintenance cost: low; small, focused packages.

### Acceptance criteria
- Every relationship endpoint resolves to a known entity or is rejected.
- Duplicate edges collapse; conflicting edges are recorded, not silently merged.
- Cycles are detected and traversal is bounded.
- Equivalent input yields byte-identical entity/relationship sets (determinism).
- No data races under concurrent read.

**Blocker:** Depends on M3.5 relationship-model acceptance. Do not implement until M3.5
is accepted.

---

## Candidate 2 — Correlation findings and severity/confidence aggregation (blocked on M3.5)

**Problem statement:** The untracked correlation engine produces relationships only — no
findings, no severity/confidence aggregation, no deduplication of cross-rule findings,
no evidence merging across rules. Correlation cannot elevate or explain findings.

**Security objective:** Let correlation produce findings that represent cross-rule
exposure, with aggregated severity and confidence and full evidence provenance.

**Intended user:** Reviewers consuming NULQ reports who need to understand combined
exposure rather than isolated rule findings.

**Concrete use cases:**
- A writable root-owned SUID executable (FS-002 MEDIUM) executed by a privileged
  process (PROC-001 HIGH) on a non-nosuid mount → correlated HIGH finding with combined
  evidence.
- Multiple rules flagging the same executable → single correlated finding.

**Expected output:** Correlated findings with severity/confidence derived from
constituent evidence, explicit limitations, and aggregated evidence references.

### Architecture
- Extend `internal/engine/correlation` (accepted only after M3.5) to emit
  `models.Finding` in addition to `Relationship`.
- Aggregation layer merges rule findings + correlation findings, dedups by stable ID,
  re-validates referential integrity.
- Severity aggregation rule: correlation finding severity = max of constituent
  severities, but never promoted above the strongest *confirmed* constituent; low
  confidence does not raise severity (per M3.5 principle).
- Confidence aggregation: min of constituent confidences (weakest link), never
  increased by accumulation.

### Security semantics
- Confirmed fact → directly observed relationship.
- Potential exposure → relationship supported by partial evidence.
- Suspicious configuration → configuration warrants attention, boundary not crossed.
- Confirmed weakness → sufficient evidence for the conclusion.
- HIGH/CRITICAL reserved for relationships that plausibly cross into root/equivalent
  authority with evidence at hand.
- Confidence never promoted by accumulating low-confidence observations.

### Engineering assessment
- Complexity: medium-high.
- Dependencies: entity model (Candidate 1), `internal/engine/aggregation`,
  `internal/core/models`.
- Performance cost: linear in findings; aggregation is a merge pass.
- Testing: positive/negative/unavailable correlation scenarios; severity boundary
  cases; confidence monotonicity; dedup consistency.
- Backward compatibility: correlation findings added to report; existing rule findings
  unchanged.
- Security risks: none (read-only).
- False-positive risk: controlled by conservative aggregation (never promote severity
  on low confidence).
- Maintenance cost: medium; aggregation semantics must be documented and tested.

### Acceptance criteria
- Correlation findings carry evidence references that resolve.
- Severity of a correlated finding never exceeds the highest confirmed constituent.
- Confidence is the weakest-link minimum; never increased by accumulation.
- Equivalent input → identical correlated finding set (determinism).
- No finding cites evidence that does not exist (referential integrity).

**Blocker:** Depends on M3.5 correlation acceptance and Candidate 1 (entity model).

---

## Candidate 3 — Deterministic serialization and report stability

**Problem statement:** NULQ report JSON is not byte-deterministic across identical scans:
`ScanInfo.StartedAt/FinishedAt`, `Observation.CollectedAt`, and `Finding.DetectedAt` are
wall-clock timestamps. Report ID depends on start time. Consumers cannot diff two scans
of the same system to detect change.

**Security objective:** Make reports reproducible so identical system state yields
byte-identical JSON (modulo intentionally dynamic fields that are clearly marked).

**Intended user:** Compliance and pipeline consumers who need reproducible assessment
artifacts.

**Concrete use cases:**
- CI diff of two NULQ reports on the same host shows only real changes.
- Archived assessments are verifiable against a re-run.

**Expected output:** A deterministic-report mode (or default) where timestamps are
normalized to the scan start time or omitted; report ID derived from stable content;
observations/findings/evidence sorted.

### Architecture
- No new package; modify `internal/app/app.go` `buildReport` and `models/report.go`
  `Normalize` to accept a deterministic-clock option.
- `ScanInfo.ReportID` derived from hostname + stable content hash (observations +
  findings) rather than start time, or keep start time but document non-determinism.
- Add `--deterministic` flag (or make default) that zeroes/normalizes timestamps.
- JSON maps sorted (Go encodes maps in sorted key order already).

### Security semantics
- Reproducibility supports auditability, not a security property itself.
- Dynamic fields (if retained) are explicitly marked `dynamic: true` in documentation.

### Engineering assessment
- Complexity: low.
- Dependencies: `internal/app`, `internal/core/models`, `internal/cli`.
- Performance cost: none (hash of in-memory report).
- Testing: determinism test — two scans of identical fixture produce identical JSON.
- Backward compatibility: schema unchanged; optional flag or normalized default.
- Security risks: none.
- False-positive risk: none.
- Maintenance cost: low.

### Acceptance criteria
- `go test -run TestDeterministicReport` passes: two `app.Scan` calls on identical
  observation input produce byte-identical JSON (when deterministic mode enabled).
- Schema validation still passes.
- Dynamic fields documented.

---

## Candidate 4 — Mount-context and bind-mount relationship modeling

**Problem statement:** Mount resolution (`ResolveMount`) picks longest-prefix mount point
but does not record bind-mount relationships, mount propagation, or nested-mount
shadowing. A bind-mounted executable's effective mount context may be misattributed.

**Security objective:** Correctly associate filesystem objects with their effective mount
context, including bind mounts and nested mounts, so mount-flag analysis (nosuid/noexec)
is applied to the right mount.

**Intended user:** Rules and correlation evaluating mount-flag impact on executables.

**Concrete use cases:**
- A root-owned SUID executable bind-mounted from a nosuid partition onto a non-nosuid
  path: which mount's flags govern execution?
- Nested mounts where a child mount overrides parent flags for a subtree.

**Expected output:** Mount-context observations that record effective flags per path,
including bind-mind source and propagation, used by mount-flags and SUID rules.

### Architecture
- Extend `internal/platform/linux/filesystem/mounts.go` `Mount` with bind source and
  propagation fields parsed from mountinfo optional field.
- `ResolveMount` returns effective mount plus bind-source chain.
- Collector attaches `effective_mount_point`, `effective_nosuid`, `effective_noexec`,
  `bind_source` to file/dir/process observations.

### Security semantics
- Mount flags apply to the mount where the inode resides, not necessarily the path's
  namespace-visible mount (bind mounts complicate this).
- nosuid/noexec evaluated against effective mount context.
- Unknown mount context → UNKNOWN, never assumed permissive.

### Engineering assessment
- Complexity: medium.
- Dependencies: `internal/platform/linux/filesystem`.
- Performance cost: minimal (already parsing mountinfo).
- Testing: mountinfo parsing fixtures with bind mounts, nested mounts, escaped fields.
- Backward compatibility: new optional attributes; existing attributes unchanged.
- Security risks: none.
- False-positive risk: moderate if bind context misattributed; mitigated by UNKNOWN.
- Maintenance cost: low-medium.

### Acceptance criteria
- Mountinfo fixtures with bind mounts resolve to correct effective mount.
- Escaped mountinfo fields parse correctly.
- Effective nosuid/noexec attributes match kernel semantics for test fixtures.

---

## Candidate 5 — Security-control and hardening posture expansion

**Problem statement:** NULQ evaluates sysctl hardening (NULQ-SYS-001) and MAC posture
(NULQ-SYS-002) but does not assess capabilities, seccomp, namespaces, systemd unit
security settings, cron, or sudoers policy (deliberately, since sudoers is not
evaluated).

**Security objective:** Broaden configuration-hardening coverage within read-only
constraints, without claiming exploitability.

**Intended user:** Hardening-review consumers wanting broader posture coverage.

**Concrete use cases:**
- Capability bounding set of privileged processes.
- Seccomp profile of services.
- Systemd unit `ProtectSystem`, `ProtectHome`, `NoNewPrivileges` settings.
- Kernel.unprivileged_userns_clone (already partially in sysctl baseline).

**Expected output:** New observation kinds (`system.capability`, `system.seccomp`,
`system.systemd_unit`) and rules (INFO/LOW severity, conservative, no exploit claims).

### Architecture
- New collectors reading `/proc/<pid>/status` (CapBnd, Seccomp), systemd unit files
  (read-only, no D-Bus), without executing services.
- New rules with `Required` kinds; skipped when data unavailable.
- Severity LOW/INFO only; explicit limitations that configuration ≠ exploitability.

### Security semantics
- Capability presence ≠ authority exercised.
- seccomp/profile presence ≠ exploit prevention proven.
- All findings contextual, LOW/INFO, with limitations.

### Engineering assessment
- Complexity: medium.
- Dependencies: procfs parsing, systemd unit file parsing (simple INI-like).
- Performance cost: minimal (read-only file reads).
- Testing: synthetic `/proc` and systemd unit fixtures.
- Backward compatibility: new kinds/rules; existing rules unchanged.
- Security risks: none (read-only).
- False-positive risk: controlled by LOW/INFO severity and explicit limitations.
- Maintenance cost: medium (new domain knowledge to maintain).

### Acceptance criteria
- New rules produce findings only when required observations present.
- All new findings LOW or INFO with limitations.
- No exploitability claims.
- Unit tests for each new rule (positive, negative, unavailable).

---

## Candidate 6 — Rule extensibility and detection policy architecture

**Problem statement:** Rules are statically registered in `internal/rules/rules.go`
(8 rules). There is no mechanism for operators to author, enable, disable, or policy-gate
detection rules without recompiling.

**Security objective:** Allow operators to customize detection policy (rule set,
severity overrides, fail-on thresholds) while preserving the conservative default and
read-only constraint.

**Intended user:** Operators deploying NULQ in varied environments.

**Concrete use cases:**
- Disable NULQ-ID-001 `docker` HIGH finding in a container-host environment where it is
  expected.
- Override severity of NULQ-SYS-001 parameters per-site baseline.

**Expected output:** A detection-policy config file (JSON/YAML) selecting rules and
severity overrides; validated at CLI startup; no arbitrary code execution.

### Architecture
- New `internal/detection/policy` package — policy document, rule selection, severity
  override validation (cannot lower HIGH to INFO without explicit opt-in? or can raise
  but not fabricate).
- CLI `--policy` flag; policy loaded read-only.
- Policy cannot add new detection logic (no scripting), only select/configure existing
  rules — preserving the "no new detection without code review" safety property.

### Security semantics
- Policy can narrow scope (disable rules) but cannot broaden detection beyond registered
  rules.
- Severity overrides recorded in report so consumers know severity was operator-adjusted.
- Fail-on threshold unaffected by policy (separate contract).

### Engineering assessment
- Complexity: medium.
- Dependencies: `internal/cli`, `internal/engine/registry`, `internal/app`.
- Performance cost: none (config parse at startup).
- Testing: policy validation tests (invalid IDs rejected, unknown severities rejected).
- Backward compatibility: default policy = all registered rules (current behavior).
- Security risks: none (no code execution from policy).
- False-positive risk: none (policy only narrows).
- Maintenance cost: low.

### Acceptance criteria
- `--policy` with invalid rule ID → usage error (exit 2).
- Policy file read-only; never executed.
- Default policy reproduces current rule set exactly.
- Overridden severities reflected in report.

---

## Ranking

| Rank | Workstream | Security value | Architectural fit | Effort | Evidence quality | FP risk | M3.5 dependency |
|---|---|---|---|---|---|---|---|
| 1 | Entity model + validated relationship graph | High | High (core gap) | Medium | High | Low | **Yes (blocked)** |
| 2 | Correlation findings + severity/confidence aggregation | High | High (core gap) | Medium-High | High | Low | **Yes (blocked)** |
| 3 | Deterministic serialization | Medium | Medium | Low | Medium | None | No |
| 4 | Mount-context / bind-mount modeling | Medium-High | Medium | Medium | Medium | Moderate | No |
| 5 | Security-control hardening expansion | Medium | Medium | Medium | Medium | Low | No |
| 6 | Rule extensibility / detection policy | Low | Low-Medium | Medium | Medium | None | No |

**Recommendation:** M4 should focus on Workstreams 1 and 2 (the core relationship /
correlation gap), but **only after M3.5 acceptance validates the existing correlation
engine and evidence integrity**. Until then, M4 preliminary work can proceed on
Workstreams 3, 4, 5, and 6, which are independent of the unverified correlation layer.
Workstream 6 (policy) is lowest priority and could be deferred beyond M4.
