# M4 Capability Inventory

**NULQ — M4 architecture & engineering blueprint**

This document inventories every major subsystem of NULQ as it exists in the source
code, documents its current capabilities and gaps, and assesses whether each area is a
sound foundation for M4.

**Gate note:** M3.5 was not completed, so no M3.5 acceptance evidence exists for any of
these subsystems. Inventory entries marked "unverified" reflect source inspection only,
not accepted milestone status.

## Source layout reference

| Package / path | Role |
|---|---|
| `cmd/nulq` | CLI entry point (`main`) |
| `internal/app` | Scan wiring: collectors + selected rules + report building (`app.go`) |
| `internal/cli` | Flags, output routing, exit codes (`cli.go`, `flags.go`, `scan.go`, `system.go`, `rules.go`, `version.go`) |
| `internal/core/models` | Observation/evidence/finding/report contracts (`observation.go`, `evidence.go`, `finding.go`, `report.go`, `severity.go`, `attributes.go`, `filemode.go`) |
| `internal/core/errors` | Typed classified error model (`errors.go`) |
| `internal/core/interfaces` | `Collector`, `Rule`, `ObservationSet` contracts (`interfaces.go`) |
| `internal/engine/registry` | Rule registry + selection (`registry.go`) |
| `internal/engine/store` | Immutable in-memory observation store (`store.go`) |
| `internal/engine/aggregation` | Finding/evidence merge, dedup, referential integrity (`aggregation.go`) |
| `internal/engine/executor` | Collector + rule execution under bounded concurrency (`executor.go`) |
| `internal/engine/correlation` | **Untracked, in-progress** correlation engine (`engine.go`, `scenarios/scenarios.go`) — NOT part of any accepted milestone |
| `internal/evidence` | Evidence builder citing observations (`evidence.go`) |
| `internal/lab` | Lab manifest, JSON schema validator, verdict engine (`manifest.go`, `schema.go`, `validate.go`, `summary.go`) |
| `internal/platform/linux/acl` | POSIX ACL parse + effective-permission evaluation (`acl.go`) |
| `internal/platform/linux/filesystem` | Filesystem collector: mountinfo, perms, traversal (`collector.go`, `mounts.go`, `perms.go`, `names.go`) |
| `internal/platform/linux/identity` | Identity collector (`collector.go`) |
| `internal/platform/linux/process` | Process collector (`collector.go`) |
| `internal/platform/linux/system` | System collector (sysctl, LSM) (`collector.go`) |
| `internal/reporting` | JSON/JSONL/Markdown/terminal renderers + sanitizers (`machine.go`, `markdown.go`, `terminal.go`, `sanitize.go`) |
| `internal/rules/{filesystem,identity,process,system}` | 8 registered detection rules |
| `internal/rules/rules.go` | Explicit rule registration |
| `pkg/api` | Public report types for external consumers (`api.go`) |
| `schemas/nulq-report-v1.schema.json` | JSON report schema (v1.1) |
| `tests/integration` | End-to-end fixture scenarios driving `app.Scan` |
| `tests/fixtures`, `tests/scenarios` | Fixtures and scenario definitions |
| `.github/workflows/ci.yml` | CI: gofmt, vet, test, race, amd64+arm64 cross-compile, smoke test |
| `.github/workflows/release.yml` | Release on `v*` tags |

---

## 1. Linux collectors

**Current implementation:**
- `internal/platform/linux/filesystem/collector.go` — bounded traversal per usable mount
  point (`filepath.WalkDir`), publishes `KindFile` (SUID/SGID only), `KindDirectory`
  (world-writable only), `KindMount`, `KindPathEntry`, `KindFilesystemScan` summaries.
  Excludes pseudo-filesystems, container storage, snapshot trees, kernel virtual paths.
  Respects `--max-files` budget; reports truncation explicitly.
- `internal/platform/linux/identity/collector.go` — group membership observations.
- `internal/platform/linux/process/collector.go` — process observations (PID, PPID, UID,
  EUID, GID, EGID, groups, start time, executable path/context only; never cmdline, env,
  memory, fds, maps).
- `internal/platform/linux/system/collector.go` — sysctl parameters, LSM/security-control
  state, system info.
- `internal/platform/linux/acl/acl.go` — reads `system.posix_acl_access`/`default` xattrs,
  parses kernel v2 binary ACL, validates canonical order/mask, evaluates effective
  permissions (owner/named-user/group/named-group/other with mask and supplementary
  groups).

**Gaps:**
- No container runtime detection beyond a boolean flag.
- No namespace inspection beyond what system info records.
- No capability bounding-set or ambient capability observation.
- No seccomp/app armor profile detail beyond active/enforcing state.
- Process collection limited by design (no cmdline/env/fd/maps) — intentional, correct
  for read-only posture, but limits process-relationship depth.

**Test coverage:** collector tests exist for filesystem, identity, process, system, acl,
mounts. ACL has a fuzz target (`FuzzParseACL`) and live-xattr test.

**Correctness risks:** unverified (M3.5 not done). The ACL parser and mounter appear
careful but lack an M3.5 adversarial review.

**M4 relevance:** High. Collectors are the observation source; any M4 relationship or
detection capability depends on what they emit.

---

## 2. Observation normalization

**Current implementation:**
- `internal/core/models/observation.go` — closed vocabulary of 10 kinds, stable
  content-derived IDs (`ObservationID` = SHA-256 of kind+resource, first 6 hex bytes),
  status enum (complete/partial/unavailable/error), immutable after `NewObservation`,
  attribute map cloned on publication.
- `internal/core/models/attributes.go` — canonical string encoding for modes (4 octal),
  booleans, IDs, RFC3339 timestamps, comma-separated sorted lists.
- `internal/engine/store/store.go` — store deduplicates by ID (more complete status wins),
  orders deterministically, provides `ByKind`/`All`/`Get`/`Has`/`HasAll`.

**Gaps:**
- Timestamps: `CollectedAt` is wall-clock `time.Now()`; report ID also uses start time.
  Two scans of identical state produce different report IDs (expected) but observation
  IDs are stable (good).
- Missing vs empty fields: `Attr()` returns `(value, ok)` distinguishing absence; rules
  vary in whether they treat absence as unknown.
- No schema for observation attribute validity beyond conventions in `attributes.go`.

**Test coverage:** `models_test.go` exists.

**M4 relevance:** Foundational. Stable observation IDs are required for stable finding
IDs and evidence references across M4.

---

## 3. Process identity

**Current implementation:**
- Process observations carry PID, PPID, comm, process UID/EUID/GID/EGID, groups, start
  time, kernel-thread flag, executable path/deleted/readable/regular/mode/owner/mount
  context/nosuid/noexec, parent path/uid/mode/sticky/effective-write/exec/ACL-status.
- `AttrProcessCmdLine`, `AttrProcessEnv`, fd, memory-map attributes are explicitly NOT
  collected (enforced by design, documented).
- Process disappearance during collection: not specially handled; a process that exits
  between enumeration and attribute read yields an unavailable/error observation or is
  skipped (unverified).
- Permission-denied procfs reads: reported as unavailable observations (unverified).
- Partial process metadata: supported via `StatusPartial`.

**Gaps:**
- No start-time-based PID reuse disambiguation in the relationship model (unverified).
- No parent-PID lineage beyond numeric PPID.
- No handling of a process whose executable is unreadable vs. deleted vs. non-regular
  beyond what `writable_parent` rule does.

**M4 relevance:** Medium. M4 process relationships depend on stable process identity.

---

## 4. Filesystem analysis

**Current implementation:**
- Filesystem collector traverses usable mounts, emits SUID/SGID files and world-writable
  directories only (plus mount + PATH + scan-summary observations).
- `fileObservation` records mode, setuid/setgid, owner, group, size, writable-by-current
  user, ACL status/access/mask, effective write/exec, mount point/flags.
- `directoryObservation` records mode, sticky, world-writable, group-writable, owner,
  ACL, effective permissions, mount flags.
- Mount resolution: `ResolveMount` picks longest matching mount point (not naive prefix),
  separates per-mount vs superblock options (`HasOption` checks both).

**Gaps:**
- Only SUID/SGID files and world-writable dirs are observed — most of the filesystem is
  invisible to rules. A writable non-SUID executable, a world-readable secret file, etc.
  are not observed unless a rule requires them.
- Symlink handling: collector lstats PATH entries but file/dir observations use `Stat`
  (follows symlinks) for regular files; symlink relationships not modeled.
- ACL applied to file/dir but mount flags attached separately.

**M4 relevance:** High. Filesystem exposure modeling is central to privilege-boundary
reasoning.

---

## 5. POSIX ACL evaluation

**Current implementation:**
- `internal/platform/linux/acl/acl.go` — full kernel v2 ACL parse with validation
  (version, size, canonical tag order, required owner/group/other, named entries require
  mask, permission bits ≤ 0x7). `EvaluateFor` implements POSIX precedence: uid 0 bypass,
  named user (masked), owning group + named groups union (masked), other. `CanCreate`,
  `CanReplaceEntry` (sticky-bit aware). `EvaluateFor` returns Unknown for unreadable/
  malformed ACL — never falls back silently to mode bits.
- Collector `applyPermissions` sets `effective_write`/`effective_exec` and maps ACL
  unknown to `writable_by_current_user=unknown`.

**Gaps:**
- Default ACLs parsed and stored (`acl_default_status`, `acl_default`) but not used in
  effective permission evaluation for new-object creation.
- ACL mask semantics partially modeled (applied to named user/group and owning-group
  union; not re-evaluated against mode recompute per POSIX `acl_calc_mode`).
- No ACL entry for the file owner when named-user entries exist (POSIX: owner is
  `user_obj`, not named user).

**Test coverage:** unit tests, live-xattr test, fuzz target.

**M4 relevance:** High. COR-002 (effective permission disagreement) depends on correct
ACL semantics; M4 relationship rules need this correct.

---

## 6. Mount resolution

**Current implementation:**
- `ReadMountInfo` parses `/proc/self/mountinfo` with octal-unescaping, separates options
  / superblock options / optional fields. Malformed lines are collected as parse errors
  without discarding valid records; file-level read error makes all mount bounds unknown.
- `ResolveMount` returns longest-prefix mount point, tie-breaks by higher mount ID.
- Mount flags (`nosuid`, `nodev`, `noexec`, `ro`, `rw`) published per observation via
  `applyMount`; plus per-mount observation with `mount_options`, `super_options`.
- Exclusions: pseudo-filesystems, container storage (`/var/lib/docker`, etc.), snapshots,
  `/run` tmpfs.

**Gaps:**
- Bind mounts: a bind-mounted file resolves to the containing mount of its path; the
  bind relationship itself is not recorded.
- Mount propagation fields in mountinfo optional field are captured (`Optional`) but not
  interpreted.
- Escaped mountinfo fields: unescaped for path fields; optional field left raw.
- No nested-mount shadowing analysis beyond longest-prefix.

**M4 relevance:** Medium-High. COR-003 (mount context) and SUID/nosuid logic depend on
this.

---

## 7. Entity modeling

**Current implementation:**
- No explicit `Entity` type exists in the codebase. Observations are the unit of fact.
- The correlation engine (untracked) defines `EntityID` (string) and `EntityReference`
  (kind + id + path) but entities are not normalized objects; they are derived ad-hoc
  from observation fields (inode, UID, mount ID).
- Relationship endpoints are often `EntityID("")` (empty) — an apparent defect: source
  and target identities are not reliably populated.

**Gaps:**
- No stable entity identity separate from observation ID.
- No entity registry or entity validation.
- Relationships can reference empty/invalid entity IDs.

**M4 relevance:** High. M4 requires a real entity model. This is a genuine gap.

---

## 8. Relationship modeling

**Current implementation:**
- Untracked correlation engine defines `Relationship` (source, target, type, evidence,
  scenario_id, evidence_kind, evaluation_outcome) and 8 relationship types
  (`PROCESS_EXECUTES`, `PROCESS_RUNS_AS`, `PATH_RESOLVES_TO`, `OBJECT_OWNED_BY`,
  `DIRECTORY_CONTAINS`, `IDENTITY_CAN_WRITE`, `OBJECT_MOUNTED_ON`, `ACL_GRANTS_ACCESS`,
  `OBJECT_HAS_PRIVILEGE_METADATA`).
- `EvaluationOutcome` (confirmed/potential/insufficient/contradicted/unknown) duplicated
  between `models/severity.go` (committed) and `correlation/engine.go` (untracked) —
  divergence risk.
- Relationship construction has apparent defects: empty entity IDs, self-referential
  edges (inode → inode), `PATH_RESOLVES_TO` used for process-pair relationships (semantic
  misuse), no deduplication, no cycle handling, no bounded traversal.

**Gaps:**
- Relationships are not validated (no endpoint existence check).
- No duplicate-edge detection or conflicting-edge resolution.
- No graph traversal, no bounded depth.
- Direction semantics inconsistent (`OBJECT_OWNED_BY` source=dir owner target=exe inode).

**Test coverage:** none for correlation (untracked package has no tests; integration test
is a debug-style smoke test).

**M4 relevance:** High. M4 relationship-aware detection needs a validated relationship
model. This is a core gap.

---

## 9. Correlation engine

**Current implementation:**
- Untracked `internal/engine/correlation/engine.go` — `Engine.Run()` evaluates COR-001
  through COR-005 over process/file/dir/mount observations, sorts relationships
  deterministically by source/target/type.
- Wired into `executor.Run()` via uncommitted `executor.go` change (`result.Correlation`).
- `scenarios/scenarios.go` defines COR-001..COR-005 scenario metadata (required kinds,
  expected outcome, rationale, limitations).

**Gaps:**
- Not part of any accepted milestone; no tests; not in CI.
- Produces relationships only — does not produce findings or modify severity/confidence.
- `EvaluationOutcome` duplicated from models package (divergence).
- No rule dependency handling, no evidence merging, no deduplication, no finding
  identity from relationships.
- COR-005 combines boolean flags globally (hasSetUID && hasWorldWritable && …) losing
  per-object provenance — evidence integrity risk.

**Test coverage:** none.

**M4 relevance:** High but blocked. M4 correlation cannot build on this until M3.5
acceptance validates it.

---

## 10. Detection rules

**Current implementation:** 8 rules registered in `internal/rules/rules.go`:

| Rule | Module | Required kinds | Default severity | Notes |
|---|---|---|---|---|
| NULQ-ID-001 | identity | group_membership | LOW | Privileged groups (docker, podman, lxd, lxc, libvirt, disk HIGH; wheel/sudo/admin/root LOW; adm/input Low-Medium) |
| NULQ-FS-001 | filesystem | file | INFO | SUID/SGID inventory; HIGH only for root-owned writable SUID executable without nosuid |
| NULQ-FS-002 | filesystem | directory, file | MEDIUM | World-writable dirs; HIGH for replaceable root-owned SUID child without nosuid |
| NULQ-FS-003 | filesystem | path_entry | LOW | Empty/relative/writable PATH entries |
| NULQ-FS-004 | filesystem | file, directory, mount | INFO | Mount flags contextualize SUID executables / world-writable dirs |
| NULQ-PROC-001 | process | process | MEDIUM | Writable-parent executable replacement |
| NULQ-SYS-001 | system | sysctl | LOW | Kernel sysctl hardening baseline (12 parameters) |
| NULQ-SYS-002 | system | security_control, system_info | LOW | MAC posture (SELinux/AppArmor enforcing) |

**Gaps:**
- No rules for capabilities, namespaces, seccomp, systemd, cron, sudoers.
- No cross-rule correlation findings (correlation engine doesn't emit findings).
- Conservative by design — deliberate, correct.

**M4 relevance:** Medium. M4 likely adds rules, but must preserve conservative semantics.

---

## 11. Evidence provenance

**Current implementation:**
- `internal/evidence/evidence.go` — builder collapses duplicate citations
  (`EvidenceID` = SHA-256 of observation ID + field), records observation ID, resource,
  field, observed/expected value, explanation, collected-at.
- `aggregation.Merge` enforces referential integrity: every finding's evidence IDs must
  exist in the evidence set; deduplicates findings by stable ID, unions evidence.
- `executor.validateRuleOutput` checks finding rule ID matches, finding validates, and
  cited evidence was returned by the rule.
- Evidence never contains secrets; `AbsentValue` (`<not observed>`) recorded for missing
  attributes.

**Gaps:**
- Evidence IDs are content-derived but only within a single rule's builder; cross-rule
  reuse of the same observation+field produces the same ID (good) but no global evidence
  registry exists.
- No validation that evidence references resolve across serialization (JSON round trip).
- `DetectedAt` on findings is wall-clock (not stable across scans) — finding ID excludes
  it (good), but finding serialization includes a non-deterministic timestamp.

**M4 relevance:** High. Evidence integrity is NULQ's credibility foundation.

---

## 12. Severity and confidence

**Current implementation:**
- `Severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL) with rank and `AtLeast`.
- `Confidence` (LOW/MEDIUM/HIGH).
- `EvaluationOutcome` (committed in `severity.go`; duplicated untracked in correlation).
- Rules assign severity per explicit switch statements; HIGH/CRITICAL reserved for
  demonstrated boundary relationships (e.g., writable root SUID).
- Finding `Validate()` requires non-empty ID, rule ID, title, resource, valid severity,
  valid confidence, non-empty evidence, non-empty explanation.

**Gaps:**
- Severity aggregation across rules: none (findings stay per-rule).
- Confidence not aggregated; no confidence propagation.
- No formal link between `EvaluationOutcome` and finding severity/confidence (duplicated
  type not used by rules).

**M4 relevance:** Medium. M4 correlation needs severity/confidence aggregation semantics.

---

## 13. Finding deduplication

**Current implementation:**
- `aggregation.Merge` dedups findings by stable `Finding.ID` (rule ID + resource + title),
  unions evidence references.
- `models.SortFindings` orders by severity desc, rule ID, resource, title, ID.

**Gaps:**
- No cross-rule dedup of findings that describe the same condition via different rules
  (that is correlation's job, not implemented).
- No near-duplicate detection (same resource, different rule).

**M4 relevance:** Medium.

---

## 14. JSON reporting

**Current implementation:**
- `models.Report` — schema version 1.1, tool, host, scan, findings, evidence,
  observations (optional), stats, coverage, limitations.
- `report.Normalize()` — ensures non-nil slices, sorts findings deterministically.
- `Report.MaxSeverity()`, `FindingCountBySeverity()`.
- Renderers: JSON (indented), JSONL (one object per line), Markdown, Terminal.
- `sanitize.go` — strips control characters from terminal/Markdown output (escape
  injection protection).
- Output files created 0600.

**Gaps:**
- `Observations` omitted by default (`IncludeObservations` flag) — evidence traceability
  reduced in default reports.
- `DetectedAt` and `CollectedAt` are wall-clock; report JSON is not byte-deterministic
  across scans of identical state (timestamps differ). Report ID is stable for
  hostname+start time but start time differs.
- `ScanInfo.ReportID` stable given same hostname+start time only.

**M4 relevance:** Medium. Deterministic serialization is an M4 concern.

---

## 15. CLI behavior

**Current implementation:**
- Commands: `scan`, `system info`, `rules list`, `version`, `help`.
- Exit codes: 0 OK, 1 runtime failure, 2 usage error, 3 `--fail-on` threshold breach.
- `--fail-on` validated via `ParseSeverity`; exit 3 when `MaxSeverity().AtLeast(failOn)`.
- Rule/module selection validated before scanning (typo = usage error).
- Concurrency, timeouts, max-files, output, format, color, quiet, verbose flags.

**Gaps:**
- CI smoke-test defect: builds `/tmp/nulq-amd64`, runs `./bin/nulq` (nonexistent).
- `--fail-on` contract not covered by unit tests (only CI smoke script).

**M4 relevance:** Medium. CLI contract tests are an M4 validation item.

---

## 16. Schema validation

**Current implementation:**
- `schemas/nulq-report-v1.schema.json` — JSON Schema v1.1 report contract.
- `internal/lab/schema.go`, `validate.go`, `schema_test.go`, `validate_test.go` — schema
  validator + lab verdict engine.
- No JSON Schema validator run in CI (no external dependency; `go.sum` absent).
- No schema-version migration strategy.

**Gaps:**
- Schema not validated in CI.
- No mechanism to reject structurally invalid findings at render time beyond `Validate()`.

**M4 relevance:** Low-Medium.

---

## 17. CI and release engineering

**Current implementation:**
- CI (`ci.yml`): gofmt, vet, test, race, amd64+arm64 cross-compile (CGO_ENABLED=0),
  smoke test (`version`, `rules list`, `system info`, `scan`), `--fail-on` contract,
  README exit-codes check. Runs on `push`/`pull_request` to `master`. `contents: read`.
- Release (`release.yml`): on `v*` tags, test, `make release`, verify checksums, upload
  artifacts, `softprops/action-gh-release`. `contents: write`.
- `make build` (host arch), `make release` (amd64+arm64 + SHA256SUMS), `make verify`,
  `make lab-*` (Docker lab scripts).

**Gaps:**
- **Confirmed CI defect:** smoke test references `./bin/nulq` but build output is
  `/tmp/nulq-amd64`. This step would fail on CI.
- No schema validation in CI.
- No fuzzing in CI.
- `go 1.24.x` in release vs `1.24` in CI (minor inconsistency).
- Lab Docker E2E blocked by policy (daemon reachable but deliberately unused).

**M4 relevance:** Medium. CI repair is a prerequisite for trustworthy M4 validation.

---

## Cross-cutting gaps relevant to M4

1. **No entity model.** Relationships reference ad-hoc IDs, often empty.
2. **Correlation engine not accepted.** Untracked, untested, not in CI.
3. **`EvaluationOutcome` duplicated.** Committed (`models/severity.go`) vs untracked
   (`correlation/engine.go`).
4. **No cross-rule finding dedup / correlation findings.**
5. **CI smoke-test path defect.**
6. **No deterministic serialization** (wall-clock timestamps).
7. **No fuzzing in CI.**
8. **M3.5 acceptance missing** — no verified foundation for M4 to build on.

## M4 readiness conclusion

The M2/M3 detection core (rules, collectors, ACL, store, aggregation, reporting) is
implemented and tests pass, but **M3.5 acceptance is absent**, so the relationship model,
evidence integrity, and correlation foundations are unverified. M4 should not assume
these are sound; the implementation plan (`m4-implementation-plan.md`) makes M3.5
acceptance a prerequisite gate for the stages that depend on them.
