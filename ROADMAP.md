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
- Rule registry with validation and selection.
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
containers, namespaces, relationship graph.

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
Verified result: 32/32 supported scenarios, 5 unsupported, 0 missing,
0 unexpected, 0 unaccounted findings, 0 duplicate findings, 0 dangling
evidence, 5/5 schema-valid.

## M2 — Linux discovery depth — **implementation complete — CONDITIONALLY ACCEPTED**

Objective: richer shared filesystem and process observations without changing
the architecture. All four deliverables are implemented; the milestone is
accepted conditional on documented environmental verification limitations.

Completed deliverables:

- **Process observations** from `/proc/<pid>` with bounded, race-aware collection.
  `nulq system info` emits 354 `process.info` observations; 338 observed in a
  full scan. Collector reads only `/proc/<pid>/stat`, `/proc/<pid>/status` and
  the `exe` symlink; never reads prohibited sensitive data (`/proc/PID/{environ,
  cmdline, mem, maps, fd}`). PID-reuse guard via `starttime`. Budget-bounded by
  `DefaultMaxProcesses = 8192`. Kernel threads detected and excluded. 123 top-level
  tests pass, coverage 90.4% in the process collector.

- **Mount flag analysis** (`nosuid`, `noexec`) as first-class observations.
  `NULQ-FS-004` is now registered in `internal/rules/rules.go`; 8 rules total.
  Reports SUID/SGID on `nosuid` mounts and world-writable on `noexec` mounts at
  INFO/MEDIUM confidence, with explicit text that the flag constrains execution
  and is not a weakness in itself. Mountinfo parser uses longest-boundary
  resolution with deterministic tie-break. Parser fuzzing passes (2.9M execs, no
  corpus written). Coverage 87.9% after registration.

- **ACL-aware permission evaluation** where POSIX ACLs are readable.
  POSIX ACL v2 xattr parser fixed for kernel `ACL_UNDEFINED_ID` defect; every
  real ACL is now correctly parsed and evaluated. `acl.EvaluateFor` at 100%
  coverage. Live xattr tests validate real-ACL handling. The CLI now reports
  `acl_status=present` with mask and `effective_write=denied` for files with
  genuine POSIX ACLs.

- **Directory containment analysis** (writable parent of a privileged file).
  New rule `NULQ-PROC-001` (module `process`, category `permissions`,
  `Required: [process]`) consumes process observations during normal `scan`.
  Eight non-silent outcomes plus a silent case keep four categories distinct:
  inventory, exposure, potential privileged impact, confirmed privilege-boundary
  weakness. A writable parent directory alone never yields a privilege finding.
  22-case table test plus 4 structural tests (grouping, inconsistency, required-
  kind, cancellation) all pass. Synthetic end-to-end through the real `app.Scan`
  pipeline produces 1 INFO/MEDIUM finding with 17 resolving evidence refs and
  schema-valid JSON. Integration test scenarios SCN-PROC-001…004 exercise the
  full pipeline without Docker or root.

Acceptance: all four capabilities are implemented, all 8 rules registered,
process observations consumed in normal scans, writable-parent relationships
produce evidence-backed findings, UNKNOWN states stay conservative, synthetic
harness exercises the real pipeline, M1.5 is clean, every runnable gate passes,
and no material defect remains.

The remaining conditions are environmental:

- **Docker / Alpine lab E2E and container isolation** — BLOCKED by directive (daemon
  reachable but deliberately unused). No container was started; no M2-era E2E
  evidence exists. This is the only environmental blocker preventing an
  unconditional acceptance.

- **HIGH-severity live fixture** — a root-owned SUID executable in a writable
  directory cannot be created unprivileged. The HIGH branch is proven by rule-level
  tests with synthetic attributes through the real `Evaluate`, and the same
  pipeline is demonstrated end-to-end at INFO. This is a verification limit, not
  presented as live coverage.

- **Lab scenarios** — the existing lab validator replays stored reports; the
  process-specific synthetic scenarios are exercised through the Go integration
  harness. No M2 scenarios or fixtures exist in `lab/manifest.json` (process,
  acl, nosuid, noexec each occur 0 times). Artifacts are M1.5-era; a refresh
  depends on Docker.

Future milestones unchanged:

## M3 — Privilege-boundary analysis — planned

Deliverables:

- Sudoers policy parsing (read-only, no `sudo` invocation) including includes,
  aliases, NOPASSWD and command wildcards.
- File capability observations and rules (capability sets, effective vs
  inheritable, elevated capability inventory).
- systemd unit/timer parsing: `User=`, `ExecStart=`, environment, writable
  executable dependencies.
- Cron and at jobs, including run-parts directories and ownership chains.
- Execution dependency rules that report *writable dependency of a privileged
  executor* rather than a writable file in isolation.

Acceptance: the engine distinguishes an isolated writable file from a writable
dependency of a privileged execution path, with evidence for each link.

## M4 — Advanced Linux analysis — planned

Deliverables: container/runtime indicators and group-mapping risks; namespace
inventory and divergence; kernel version and mitigation observations without
version-only exploit claims; AppArmor/SELinux policy presence; distribution
compatibility matrix; restricted-environment degradation tests.

Acceptance: checks work gracefully when `/proc`, `/sys` or security filesystems
are unavailable, and say so.

## M5 — Relationship and correlation engine — planned

Deliverables:

- Typed in-memory graph with observed vs inferred edges and observation
  references on every edge.
- Correlation rules with confidence propagation.
- Explainable chains (for example: user-writable directory → privileged unit
  executes script there → script owned by root → service runs as root).
- Reproducibility: each correlation must be reconstructable from its source
  observations.

Acceptance: every correlated finding lists the ordered relationship chain and
its evidence. See `docs/relationship-graph.md` and
`docs/correlation-engine.md` for the intended design.

## M6 — Reporting and integration — partially present

Already delivered: JSON Schema v1, JSONL, Markdown, stable IDs, exit codes,
`pkg/api`, shell/Python examples.

Remaining: stored-report queries (`findings list`, `report`), severity
baselines and diffing between scans, SARIF export evaluation, integration test
fixtures packaged for consumers.

## M7 — Hardening and release — in progress

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
