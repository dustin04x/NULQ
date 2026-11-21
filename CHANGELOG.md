# Changelog

All notable changes to NULQ are documented here. The format follows Keep a
Changelog; versions follow Semantic Versioning.

## [Unreleased]

### Added

- Report coverage contract (`coverage` object) separating execution success
  from observation completeness: per-root files and directories examined,
  traversal errors, permission-denied entries, truncation, unavailable and
  unsupported observations, recorded rule skips, deliberately excluded mount
  points, and classified failed operations (timeout, cancelled, internal).
  Schema version is now 1.1 (additive; see ADR 0009).
- M1.5 independent audit: `docs/audits/m1.5-baseline.md`,
  `docs/audits/m1.5-final-engineering-report.md`, and the severity/confidence
  contract in `docs/architecture/severity-confidence-model.md`.
- Laboratory integrity checks: duplicate findings, dangling evidence references
  and findings without evidence now fail the run. A fifth live scan exercises
  auto-discovered mount exclusions. Per-scan accounting rejects findings that
  are neither asserted nor explicitly allowed, even outside scenario scope.
- Independent source-level review (`docs/audits/m1.5-independent-source-review.md`,
  `m1.5-security-corrections.md`, `m1.5-final-acceptance.md`).
- Automated Docker laboratory under `lab/`: pinned Alpine 3.22 target,
  synthetic fixtures, scenario manifest, schema/scenario validator, isolation
  probe, Makefile targets and `lab/results/` reports.
- Engineering constitution `AGENTS.md` with an explicit host-protection policy,
  and `MISSION.md` scoped to the current milestone.
- Observation-first assessment pipeline: collectors publish normalized,
  immutable observations; rules consume a shared store.
- Linux collectors for system/kernel facts, LSMs, sysctls, execution context,
  group membership, mounts, notable filesystem entries and PATH entries.
- Typed error model distinguishing permission denial, absence, unsupported
  operations, timeouts, cancellation and internal failures.
- Rule registry with metadata validation, duplicate rejection, module and
  rule-ID selection, and unknown-selection errors.
- Bounded-concurrency engine with per-collector and per-rule timeouts,
  context cancellation, panic isolation and per-rule failure isolation.
- Aggregation with referential-integrity enforcement, deduplication and
  deterministic ordering.
- Rules: `NULQ-ID-001` privileged group membership, `NULQ-FS-001` set-owner-ID
  executable inventory, `NULQ-FS-002` world-writable directory without sticky
  bit, `NULQ-FS-003` unsafe PATH directory, `NULQ-SYS-001` kernel sysctl
  baseline, `NULQ-SYS-002` mandatory access control posture.
- Terminal, JSON, JSONL and Markdown reporting with terminal-injection
  sanitization.
- Published JSON Schema v1 and public `pkg/api` types.
- CLI: `scan`, `system info`, `rules list`, `version`; stable exit codes;
  `--fail-on` gate; quiet/verbose/colour control; file output with 0600 modes.
- Makefile (build, test, race, lint, release, checksum verification), CI and
  tag-driven release workflow.
- Documentation: architecture, privilege model, observation model, detection
  engine, evidence model, JSON schema, rule development, testing, threat
  model, relationship-graph and correlation-engine designs, and ADRs 0001–0007.
- Tests: model invariants, registry, engine isolation/timeouts, aggregation,
  collector fixtures, all rules (positive and negative), renderers, CLI exit
  codes, end-to-end scenarios, mount-parser fuzzing.

### Fixed

- `NULQ-FS-003` reported a writable PATH directory, an empty element and a
  relative entry as HIGH without observing any privileged consumer. All are
  now LOW contextual findings, with the missing execution relationship stated
  explicitly. A PATH entry after trusted locations is likewise LOW.
- `NULQ-FS-001` reported a non-standard SUID location and non-root ownership
  as MEDIUM. Standard-directory inventory is now INFO, non-standard location
  and non-root ownership are LOW, self-owned writable files are LOW, another
  account's writable privileged executable is MEDIUM, and only a writable
  root-owned executable is HIGH. Set-owner-ID bits on non-executable files are
  inert INFO; the kernel ignores them.
- `NULQ-FS-002` escalated any world-writable PATH directory to HIGH and matched
  privileged executables in nested subdirectories by string prefix. PATH
  membership alone no longer escalates, and only a privileged executable
  directly inside the directory makes replacement possible (HIGH).
- `NULQ-SYS-002` could report "no MAC module enforcing" while AppArmor was
  enforcing, because a permissive SELinux finding cleared the overall flag.
  Enforcement is now taken from each module's state, and one permissive module
  cannot cancel another enforcing one.
- `NULQ-FS-002` escalated any executable with SUID or SGID, including
  user-owned and root-group files, and claimed HIGH confidence without an
  observed execution. HIGH now requires a directly replaceable **root-owned
  SUID** executable, confidence is MEDIUM, and a sticky directory owned by the
  assessed user no longer suppresses a real replacement path.
- `NULQ-SYS-002` treated an advertised MAC module with no usable state file as
  not enforcing. Unknown state now suppresses the generic finding rather than
  inventing a disabled module.
- The laboratory validator could ignore unasserted findings outside a
  scenario's `scope`, and its expected/actual counters did not reveal this.
  Every finding is now accounted for per scan; unaccounted findings fail.
- `make lab-build` intermittently exited 141 (SIGPIPE) after a successful image
  build because `nulq version | head -n 1` closed the pipe. The scripts now
  consume the full stream; success and status exit codes are truthful.
- The published schema's observation-ID pattern rejected the IDs the binary
  actually emits for kinds containing underscores (`filesystem.path_entry`,
  `identity.group_membership`, `system.security_control`). The pattern now
  permits underscores; the laboratory's independent validator caught this.
- Coverage classification: a rule skipped because its data category is empty
  (no set-owner-ID files, for example) was treated as limited coverage. It is
  now recorded as "not applicable" and does not downgrade coverage; only
  unsupported environment data does.
- PATH entries that are symlinks (for example `/bin` → `/usr/bin`) were
  evaluated using the symlink's own mode, producing a false HIGH finding.
  Permission semantics now follow the resolved target and record the link.
- A global traversal budget starved later mount points once `/` consumed it;
  the budget is now per filesystem and truncation is reported per root.
- Container storage and snapshot mounts were traversed as host filesystems,
  duplicating privileged executables. They are excluded by default and can be
  assessed explicitly with `--root`.
- Non-directory bind mounts (for example a swapfile) produced meaningless
  truncated scan summaries.

## [0.1.0] — not yet released

See Unreleased. The version is released only after M7 quality gates pass.
