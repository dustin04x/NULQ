# NULQ roadmap

Milestones are complete only when their acceptance criteria are demonstrated by
execution evidence, not because files exist.

## M0 — Research and architecture — **complete**

Delivered:

- Architecture proposal (`docs/architecture.md`).
- Linux privilege model research (`docs/linux-privilege-model.md`).
- Observation, evidence and detection-engine contracts.
- Threat model (`docs/threat-model.md`).
- ADRs 0001–0007.
- Repository reconnaissance: empty Go project, no prior implementation.

Acceptance: the architecture explains how a low-level observation becomes an
evidence-backed finding. Satisfied by the observation pipeline design and the
implemented M1 flow.

## M1 — Foundation — **complete**

Delivered:

- Go module, `cmd/nulq`, CLI with `scan`, `system info`, `rules list`,
  `version`.
- Version metadata with linker flags.
- System, identity and filesystem collectors.
- Core models: observations, evidence, findings, report, schema version.
- Typed error classes and honest unavailability handling.
- Rule registry with metadata validation, duplicate rejection, module and
  rule-ID selection, and unknown-selection errors.
- Bounded-concurrency executor with per-rule timeout, panic isolation,
  per-rule error isolation and prerequisite skipping.
- Aggregation with referential-integrity checks, deduplication and
  deterministic ordering.
- Six rules across identity, filesystem and kernel hardening.
- Terminal, JSON, JSONL and Markdown reporting; published JSON Schema.
- Exit-code contract and `--fail-on`.
- Makefile, CI, release workflow, checksums.
- Unit, integration, CLI and rule tests; race-clean.

Acceptance: the binary executes on a real Linux host, inspects it, runs real
rules and emits valid JSON. Demonstrated on the development host.

Known gaps deliberately deferred: sudo policy, capabilities, systemd, cron,
containers, namespaces, relationship graph — all now delivered in M2/M3.

## M1.5 — Governance and Docker laboratory — complete

Delivered:

- `AGENTS.md` engineering constitution with a mandatory host-protection policy.
- `MISSION.md` describing the laboratory mission and its acceptance criteria.
- Coverage contract (`coverage` object, schema 1.1) distinguishing execution
  success from observation completeness, including permission-denied and
  truncation accounting per filesystem root.
- Pinned Alpine 3.22 target image with synthetic, deterministic fixtures.
- Docker Compose laboratory: non-root, capability-free, read-only root
  filesystem, no network, no host namespaces, no Docker socket.
- Scenario manifest and validator that run the real binary, validate reports
  against the published schema and judge expectations explicitly.
- Makefile lab interface, isolation probe, targeted cleanup and reports under
  `lab/results/`.
- M1.5 independent audit: rule-by-rule semantic review, severity/confidence
  corrections, coverage exclusions and classified failures, validator integrity
  checks, and five-lab-scan coverage of the corrected semantics.

Acceptance: `make lab-test` runs unattended against Docker, validates JSON,
separates passed/failed/unsupported scenarios and exits non-zero on failure.
Verified result: 34/34 supported scenarios, 5 unsupported, 0 missing,
0 unexpected, 0 unaccounted findings, 0 duplicate findings, 0 dangling
evidence, 5/5 schema-valid.

## M2 — Linux discovery depth — **complete**

Objective: richer shared filesystem and process observations without changing
the architecture. All deliverables are implemented.

Completed deliverables:

- **Process observations** from `/proc/<pid>` with bounded, race-aware collection.
  `nulq system info` emits `process.info` observations; collector reads only
  `/proc/<pid>/stat`, `/proc/<pid>/status` and the `exe` symlink; never reads
  prohibited sensitive data (`/proc/PID/{environ, cmdline, mem, maps, fd}`).
  PID-reuse guard via `starttime`. Budget-bounded by `DefaultMaxProcesses`.
  Kernel threads detected and excluded.
- **Mount flag analysis** (`nosuid`, `noexec`) as first-class observations.
  `NULQ-FS-004` is registered; reports SUID/SGID on `nosuid` mounts and
  world-writable on `noexec` mounts at INFO/MEDIUM confidence, with explicit
  text that the flag constrains execution and is not a weakness in itself.
  Mountinfo parser uses longest-boundary resolution with deterministic tie-break.
  Parser fuzzing passes.
- **ACL-aware permission evaluation** where POSIX ACLs are readable.
  POSIX ACL v2 xattr parser fixed for kernel `ACL_UNDEFINED_ID` defect;
  every real ACL is correctly parsed and evaluated. `acl.EvaluateFor` at 100%
  coverage. Live xattr tests validate real-ACL handling.
- **Directory containment analysis** (writable parent of a privileged file).
  `NULQ-PROC-001` consumes process observations during normal `scan`.
  Eight non-silent outcomes plus a silent case keep four categories distinct:
  inventory, exposure, potential privileged impact, confirmed privilege-boundary
  weakness. A writable parent directory alone never yields a privilege finding.

Acceptance: all four capabilities are implemented, all 8 rules registered,
process observations consumed in normal scans, writable-parent relationships
produce evidence-backed findings, UNKNOWN states stay conservative, synthetic
harness exercises the real pipeline, M1.5 is clean, every runnable gate passes,
and no material defect remains.

## M3 — Privilege-boundary analysis — **complete**

All five deliverables are implemented:

- **Sudoers policy parsing** — `NULQ-ID-002` reads `/etc/sudoers` and
  `/etc/sudoers.d/` read-only, no `sudo` invocation. Handles includes,
  aliases, NOPASSWD and command wildcards. Unit-tested (positive/negative/
  unavailable).
- **File capability observations** — `NULQ-FS-005` reads `security.capability`
  xattr and inventories capability sets (permitted, inheritable, effective).
  Unit-tested (positive/negative/unavailable).
- **systemd unit parsing** — `NULQ-SYS-005` reads `.service` unit files from
  standard systemd directories, evaluates `User=`, `NoNewPrivileges=`,
  `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `CapabilityBoundingSet=`.
  Never starts/stops units or contacts PID 1 over D-Bus.
- **Cron and at jobs** — `NULQ-ID-003` reads cron directories and files,
  reports writable job files and scheduled commands. Unit-tested
  (positive/negative/unavailable).
- **Execution dependency rules** — writable dependency of a privileged executor
  is reported through `NULQ-PROC-001` with evidence for each link.

Acceptance: the engine distinguishes an isolated writable file from a writable
dependency of a privileged execution path, with evidence for each link.
Verified by rule-level tests and end-to-end `app.Scan` pipeline tests.

## M4 — Advanced Linux analysis — **partially complete**

Implemented:

- Container/runtime indicators — `NULQ-SYS-008` probes Docker socket,
  containerd socket and `/.dockerenv` without connecting to any socket.
  Lab-asserted (SYS-008 scenario).
- Kernel version and mitigation observations — `NULQ-SYS-007` reads
  `/sys/devices/system/cpu/vulnerabilities/*` and reports each mitigation
  status. Lab-asserted (SYS-007 scenario).
- AppArmor/SELinux policy presence — `NULQ-SYS-002` reports LSM state from
  each security module independently; one permissive module cannot cancel
  another enforcing one.

Not yet implemented:

- Group-mapping risks and namespace inventory/divergence.
- Distribution compatibility matrix.
- Restricted-environment degradation tests beyond current coverage.

Acceptance: checks work gracefully when `/proc`, `/sys` or security filesystems
are unavailable, and say so. Implemented checks meet this; remaining items are
planned.

## M5 — Relationship and correlation engine — **implemented**

Implemented:

- `internal/engine/correlation/engine.go` with scenarios COR-001 through COR-005
- Typed relationships with Source, Target, Type, Evidence, ScenarioID, EvidenceKind, EvaluationOutcome
- Boundary-aware `containsPath()` (no `/various` matching `/var`)
- No self-referential relationships (Source == Target not emitted)
- No empty Source/Target IDs or empty Evidence
- COR-001 (executable replacement exposure), COR-003 (mount privilege metadata) produce relationships
- COR-002, COR-004, COR-005 produce no relationships when distinct Source/Target cannot be determined

Acceptance: every emitted relationship carries observation references; observed and inferred edges are distinguishable by `EvaluationOutcome`; no relationship has empty Source, Target, or Evidence. See `docs/relationship-graph.md` and `docs/correlation-engine.md` for the intended design.

Per AGENTS.md rule 10, correlation is implemented. NULQ may be described as correlating findings through the relationship engine.

## M6 — Reporting and integration — **partially present**

Already delivered: JSON Schema v1, JSONL, Markdown, stable IDs, exit codes,
`pkg/api`, shell/Python examples.

Remaining: stored-report queries (`findings list`, `report`), severity
baselines and diffing between scans, SARIF export evaluation, integration test
fixtures packaged for consumers.

## M7 — Hardening and release — **in progress**

Delivered: race-clean tests, parser fuzzing for mount parsing, threat model,
release workflow with checksums.

Remaining: broader fuzzing (os-release, config parsers as they arrive),
performance budget regression tests, independent security review, signed
release artifacts, documentation review against behaviour, v0.1.0 tag.

## Cross-cutting backlog

- Privileged (opt-in, isolated) integration tests for root-owned fixtures.
- Baseline suppression file with explicit justification and expiry.
- Structured rule enable/disable policy per environment.
- Package metadata for distribution channels.
