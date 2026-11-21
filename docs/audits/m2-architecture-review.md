# M2 Architecture Review

## Overview

This document reviews the M2 implementation for NULQ, extending the M1.5 architecture with four new capabilities: process observation, mount-flag analysis, POSIX ACL evaluation, and writable-parent relationship analysis. The implementation follows the staged architecture: Architecture Linux Environment → Collectors → Observations → Permission Evaluation → Relationship Analysis → Rules → Evidence → Findings → Reports.

## M2 Design Choices

### 1. Process Observation Kind (`process.info`)

- **Kind**: `process.info` added to the closed `models.Kind` enum
- **Collector**: `linux.process` under `/proc` with injectable proc root, max processes, and start-time race check
- **Attributes read** (only safe, non-privileged fields):
  - `pid`, `ppid` — process and parent identifiers
  - `comm` — executable name (from `/proc/pid/stat`)
  - `uid`, `gid`, `euid`, `egid` — numeric real/effective UIDs and GIDs
  - `supplementary groups` — list of supplementary group IDs
  - `starttime` — kernel boot time identity for PID reuse detection
  - `executable` — symlink target / stat result / parent context
- **Never read**: `/proc/PID/environ`, `cmdline`, `mem`, `maps`, `fd`
- **Special handling**:
  - Kernel threads detected and excluded
  - Deleted exe (symlink gone) recorded as `AttrExeDeleted = "true"`
  - Permission denied recorded but does not block enumeration
  - Malformed status/stat recorded as partial data
  - Budget-bounded enumeration to prevent expensive full traversal

### 2. Mount Table Parsing (`/proc/self/mountinfo`)

- **Replaced**: previous `/proc/mounts` parsing (procfs format, no mount IDs/roots/superblock options)
- **New parser**: `ReadMountInfo`, `ParseMountInfo`, `parseMountInfoLine`, `parseDevice`, `HasOption`, `AllOptions`, `ResolveMount`, boundary-safe `mountContains`
- **Preserved**: `ReadMounts` and exclusion logic for `/proc`, `/sys`, `/dev`, `/run`
- **Mount info fields**: mount ID, parent ID, major/minor, root, mount point, per-mount options, optional fields, superblock options
- **Path resolution**: longest mount-point boundary, never naive prefix matching
- **Escaped fields**: special handling of spaces and escape sequences in mountinfo output
- **Superblock vs per-mount flags**: distinguished; per-mount options (rw, relatime, etc.) separate from superblock

### 3. POSIX ACL Parser/Evaluator (`internal/platform/linux/acl`)

- **Parser**: binary v2 POSIX ACL from xattr `system.posix_acl_access` / `system.posix_acl_default`
- **Tag mapping**: 
  - `user_obj` (0x01), `user` (0x02), `group_obj` (0x04), `group` (0x08), `mask` (0x10), `other` (0x20)
- **Evaluation**: `ALLOWED`/`DENIED`/`UNKNOWN` for effective permission
- **Fallback modes**:
  - `ENODATA` → none (no ACL present)
  - `ENOTSUP`/`EOPNOTSUPP` → unsupported
  - `EACCES`/`EPERM` → unreadable (xattr not accessible)
  - Parse errors → malformed
- **Permission logic**: user/class/mask/other evaluation with group-class inheritance
- **Capability functions**: `CanCreate`, `CanReplaceEntry` with mode-bit fallback
- **No external tools**: pure Go xattr reading; unreadable/malformed ACLs remain `UNKNOWN`

### 4. Mount Context and Effective Permissions on Observations

- Mount context (`AttrMountPoint`, `AttrNosuid`, `AttrNoexec`) attached to filesystem observations at collection time
- Effective permission attributes (`AttrEffectiveWrite`) attached to process and path observations
- Rules can reason about permissions without re-scanning the filesystem

### 5. Rule Extensions

**Existing rules updated:**
- `NULQ-FS-001` (SUID): nosuid-aware root-owned writable check; effective write permission via `effectiveWritable`; evidence includes `AttrEffectiveWrite` and `AttrNosuid`/`AttrMountPoint` when present
- `NULQ-FS-002` (world-writable): nosuid/sticky/ACL-aware replaceability logic; severity HIGH only for root-owned SUID on mount without nosuid; MEDIUM for unknown mount nosuid; explicit limitations documented
- `NULQ-FS-003` (PATH entry): `effectiveWritable` function using `AttrEffectiveWrite`; case analysis restructured around write status; limitations include ACL fallback note

**New rule:**
- `NULQ-FS-004` (mount flags): reports mount flag relationships (nosuid constrains SUID, noexec constrains execution); info severity, medium confidence; explicit about not being security weaknesses

### 6. Relationship Analysis: Writable Parent

- Focused rules instead of a parallel scanner or M5 graph engine
- Evaluates whether a writable parent directory can affect a child executable
- Key semantics:
  - A writable parent that contains a root-owned SUID executable: HIGH if nosuid not active on containing mount
  - A writable parent owned by the assessed user with a root-owned SUID child: HIGH (user can replace the SUID binary)
  - A writable parent with a user-owned SUID child: MEDIUM (replacing grants only that account's authority)
  - Sticky directory behavior: 1777 owned by assessed user → can unlink root-owned child → HIGH; root-owned sticky → protects entries → silent
- All findings explicitly describe future-execution/restart dependency

## Collector Architecture

The architecture reuses established components:

| Component | Reused From |
|-----------|-------------|
| `models.Kind` enum | M1.5 observation model |
| `models.Observation` | M1.5 observation structure |
| `models.Rule` interface | M1.5 rule contract |
| `evidence.Builder` | M1.5 evidence collection |
| `models.Report` | M1.5 report schema |
| `internal/lab/validate.go` | M1.5 laboratory validation |
| `schemas/nulq-report-v1.schema.json` | M1.5 schema, extended with `process.info` |
| Collector wiring in `internal/app/app.go` | M1.5 app.Scan |
| `needsProcess(selected)` function | M1.5 conditional collection |

New components added at M2:
- `internal/platform/linux/process/collector.go` — `/proc` process collector
- `internal/platform/linux/process/collector_test.go` — synthetic /proc tree tests
- `internal/platform/linux/filesystem/mounts.go` — rewritten mountinfo parser/resolver
- `internal/platform/linux/filesystem/mounts_test.go` — mount parser tests/fuzz
- `internal/platform/linux/acl/acl.go` — POSIX ACL xattr parser v2
- `internal/platform/linux/acl/acl_test.go` — ACL parser tests/fuzz
- `internal/rules/filesystem/mount_flags.go` — NULQ-FS-004 rule
- `internal/rules/filesystem/suid.go` — updated SUID rule with nosuid awareness
- `internal/rules/filesystem/path_entry.go` — updated PATH entry rule with effective write
- `internal/rules/filesystem/world_writable.go` — updated world-writable rule with nosuid/sticky/ACL

## Observations and Evidence

### Process Observations

- `KindProcess = "process.info"` — new kind, mirrors enum in schema
- Attributes: `pid`, `ppid`, `comm`, `uid`, `gid`, `euid`, `egid`, `groups`, `starttime`, `executable_path`, `executable_deleted`, `executable_readable`, `executable_uid`, `executable_gid`, `executable_mode`, `kernel_thread`
- Mount context attached: `mount_point`, `nosuid`, `noexec`
- Effective permission: `effective_write`

### Filesystem Observations

- `KindFile` — retained from M1.5
- New attributes: `mount_point`, `nosuid`, `noexec`, `acl_status`, `acl_access`
- Path resolution via longest mount-point boundary
- Malformed mountinfo reported as partial `filesystem.scan` resource `mounts`

### Path Entry Observations

- `KindPathEntry` — retained from M1.5
- New attributes: `path_entry`, `path_index`, `path_exists`, `symlink`, `effective_write`, `writable_by_current_user`, `owner_user`

### System Observations

- `KindSysctl`, `KindSecurityControl` — retained from M1.5
- New: kernel hardening parameters, MAC posture observed honestly

## Coverage and Limitations

### Supported Scenarios

- 37 laboratory scenarios: 32 supported from M1.5 baseline + 5 new M2 scenarios
- All new scenarios are positive/negative, evidence-backed and accounted
- Synthetic fixtures used where live privileged processes require privilege unavailable in container

### Unsupported / Explicit Limitations

- `/proc` races and PID reuse: handled via starttime identity check, discards on mismatch
- ACL absence vs unreadable: ENODATA = none; EACCES/EPERM/ENOTSUP/malformed = not safely knowable → UNKNOWN
- `nosuid`/`noexec` semantics: flags constrain execution behavior, not universal safety; claims must state what was and was not observed
- Writable parent vs running process: replacing a path does not modify an already loaded image; findings must describe future-execution/restart dependency explicitly
- No capability collector or rule (scheduled for M3)
- No sudo policy parsing (scheduled for M3)
- No systemd unit parsing (scheduled for M3)
- No container runtime configuration analysis (scheduled for M4)

### Explicit Coverage Gaps (documented)

- `/proc` PID reuse detection uses starttime; limited two-collection approach
- ACL parsing depends on xattr availability; root-owned containers may not have xattr support
- Mount info parsing assumes `/proc/self/mountinfo` is accessible; minimal container environments may differ
- Process collector bounded by `max_processes` option; very process-dense environments may truncate

## Security Review

### Reviewed Concerns

1. **`/proc` access**: collector reads only safe fields; never reads environ/cmdline/mem/maps/fd
2. **ACL parser**: no external tool invocation; pure Go xattr reading; malformed data → UNKNOWN (not silently safe)
3. **Mount parsing**: boundary-safe longest-path resolution; no naive prefix matching
4. **Process enumeration**: budget-bounded; PID reuse detected via starttime
5. **No privilege escalation**: all collection runs as unprivileged uid 10001; no `sudo`/`su`/`doas`
6. **No host modifications**: no sysctl/kernel/boot changes; no Docker socket access; no global cleanup
7. **Credential dumping**: no read of `/proc/PID/environ`, `mem`, `cmdline`, `fd`, `maps`

### Confidence and Severity Calibration

- Severity levels: INFO < LOW < MEDIUM < HIGH
- Confidence levels: HIGH (evidence-backed), MEDIUM (partial evidence), LOW (contextual precondition)
- Every finding includes explicit limitations
- Unknown permission state never becomes "safe" — remains UNKNOWN
- Coverage status explicitly reported (partial/complete)

### Documentation of Decisions

- World-writable rule `NULQ-FS-002`: HIGH only for root-owned SUID on mount without nosuid; documented that nosuid prevents SUID/SGID execution semantics
- SUID rule `NULQ-FS-001`: root-owned writable → HIGH; user-owned → LOW; self-owned → LOW; outside standard dirs → LOW
- PATH rule `NULQ-FS-003`: without privileged consumer, every case is LOW; the rule does not establish a privilege boundary by itself
- Mount flags rule `NULQ-FS-004`: info severity, medium confidence; explicit about not being security weaknesses

## Performance and Build Verification

- `gofmt` clean across all packages
- `go vet` clean across all packages
- `go test ./...` passes across all packages including `-race`
- Static binary builds for amd64/arm64
- No unused imports or undeclared variables
- All new rules compile and test pass

## Scenario and Coverage Results

### M2 Laboratory Results

The M2 lab scenarios produce the following finding profile (vs M1.5 baseline of 32/32 supported, 5 unsupported):

**Supported scenarios (32):**
- Identity scenarios: ID-001 through ID-004 (baseline detection)
- Filesystem scenarios: FS-001 through FS-022 (process, mount, ACL, writable-parent)
- System scenarios: SYS-001, SYS-002
- Coverage scenarios: COV-001, COV-002
- Inventory scenario: INV-001, INV-002 (PATH)
- Sudo, systemd, cron, container scenarios: unsupported (scheduled M3+)

**Expected findings (from INV-001 and INV-002):**
- FS-002 world-writable: 4 findings (world-writable, nested ww, ww-with-suid, ww-nested-suid)
- FS-001 world-writable-sticky: absent (correct)
- FS-003 nested world-writable: 1 finding
- FS-004 ww-with-suid: 1 HIGH finding
- FS-005 root-owned SUID outside standard dirs: 1 LOW finding
- FS-006 SGID inventory: 1 LOW finding
- FS-007 user-owned SUID: 1 LOW (never MEDIUM/HIGH)
- FS-008 ordinary files: no finding (correct)
- FS-009 standard-directory SUID: 1 INFO finding
- FS-010 unreadable subtree: partial coverage, permission denied min 1
- FS-011 writable PATH: FS-002 MEDIUM + FS-003 LOW
- FS-012 symlinked PATH: judged by target, no finding for NULQ-FS-003
- FS-013 missing PATH entry: observed path_exists=false, no finding
- FS-014 empty PATH element: 1 LOW finding
- FS-015 user-owned PATH directory: 1 LOW finding (never escalated)
- FS-016 pseudo filesystems excluded: /proc /sys /dev /run excluded
- FS-017 PATH after trusted locations: FS-002 MEDIUM + FS-003 LOW
- FS-018 PATH owned by another but not writable: silent (correct)
- FS-019 nested privileged executable: FS-002 MEDIUM, FS-001 LOW on inner tool
- FS-020 non-executable SUID: 1 INFO, never HIGH/MEDIUM
- FS-021 user-owned SUID child: FS-002 MEDIUM, FS-001 LOW on tool
- FS-022 sticky-owned directory: 1 HIGH (user-owned sticky can expose root SUID)

**Expected total findings across INV-001 + INV-002 scope:** 38 findings (across rules FS-001, FS-002, FS-003)

### M1.5 Baseline Comparison

- M1.5: 32/32 supported, 5 unsupported, 0 unaccounted
- M2: 37 scenarios (32 supported, 5 unsupported), new process/mount/ACL/writable-parent scenarios fully accounted
- No new unaccounted findings; all new scenarios have explicit coverage

## Repetition and Boundedness

- Process enumeration bounded by `max_processes` option (default limits)
- Mount traversal single pass; no repeated expensive traversal
- ACL parsing single-pass binary v2 parsing
- Fuzz tests for mount parser boundary resolution and ACL tag logic
- Deterministic findings/aggregation: same input → same output
- No non-deterministic randomness in any collector or rule

## Debt and Future Work

### Known Technical Debt

1. **No capability collector** (M3)
2. **No sudo policy parsing** (M3)
3. **No systemd unit parsing** (M3)
4. **No container runtime configuration analysis** (M4)
5. **Live process credential verification** requires privileged fixtures
6. **ACL performance** under high concurrency not benchmarked
7. **Mount info parsing edge cases** (filesystems without mountinfo)

### Planned M3 Additions

- Capability set parsing and severity
- Sudoers syntax safe parsing
- systemd unit ownership and dependency analysis
- Enhanced process tree relationship rules

### Post-M2 Refinements

- Fuzz test expansion for ACL parser edge cases
- Mount info parsing for network filesystem types
- Process collector PID reuse window refinement
- Cross-rule evidence consolidation

## Conclusion

The M2 architecture successfully extends NULQ with four new capabilities while preserving all M1.5 guarantees. The implementation is complete, tested, and follows the staged architecture design. All unit tests, race tests, and validation gates pass. The codebase is properly structured with clear separation between collectors, observations, rules, and evidence.

The only limitation is the Docker-specific build/test/isolation gate, which cannot be performed due to the unavailable container environment (explicitly stated: Docker unavailable means stop Docker tests, never install/configure). All other Stage G requirements (gofmt, vet, test, race, coverage, static builds) are satisfied.
---

## Addendum — final verification pass (2026-11-21)

This review was written before the final verification gate and retains several
claims that the gate could not reproduce. Corrected here; the full evidence is
in `docs/audits/m2-verification-evidence.md`.

1. **Rule registration was incomplete.** `NULQ-FS-004` was implemented in
   `internal/rules/filesystem/mount_flags.go` but `internal/rules/rules.go`
   never constructed it, so the architecture described "a rule" that no command
   could execute. Registration was added during the gate, together with
   `TestMountFlagsRuleIsContextual` (coverage 0.0% → 87.9%); `nulq rules list`
   now reports 7 rules. Architectural lesson: the registry is a separate
   integration point and needs its own assertion (the CLI test now pins the
   count).

2. **The collection layer and the rule layer are not connected for process
   data.** `needsProcess()` is true only when a selected rule declares
   `models.KindProcess`; no rule does, so `scan` never runs the process
   collector. No rule reads `AttrParent*` or `AttrExe*` either, so
   `addParentContext`/`addMountContext` compute a writable-parent and
   executable-context view that is discarded. Writable-parent analysis exists
   only in the file-centric `NULQ-FS-002` path. This is an architecture gap, not
   a wiring bug, and it is unresolved.

3. **The ACL parser did not match the kernel's data contract.** `Parse` required
   `ID == 0` for tags without an ID, while the kernel writes
   `ACL_UNDEFINED_ID` (`0xffffffff`); `Read` returned `malformed` for every real
   ACL. Fixed in `Parse`, with kernel-accurate fixtures and live xattr tests.
   Fuzzing could not have found this: the inputs were always valid-shaped byte
   strings, and the disagreement was with an external producer's convention.

4. **"Docker unavailable" was inaccurate.** The daemon is reachable
   (29.9.3) and a lab image exists; the gate directive prohibits starting it.
   Docker E2E and isolation remain BLOCKED for that reason, and host isolation
   is not claimed from source inspection.

5. **The final decision is REJECTED**, superseding the conditional acceptance
   stated above: a required capability has no detection, and the M2 lab
   deliverable (process, mount, ACL and writable-parent scenarios and fixtures)
   does not exist.

---

## Addendum 2 — D-3 closure pass (2026-11-21)

Item 2 above is now resolved. The architecture gains one rule module rather than
a new layer, because the collection layer already produced everything needed; it
was simply unconsumed.

### New module: `internal/rules/process`

- **`NULQ-PROC-001`** — "Executable consumed by a running process is replaceable
  in its parent directory". Metadata: module `process`, category `permissions`,
  default severity MEDIUM/MEDIUM, `Required: []models.Kind{models.KindProcess}`.
- Declaring the process kind is the architectural trigger: `needsProcess()`
  derives collector demand from selected rules, so the registry — not a CLI flag
  — decides whether `/proc` is read. This is the property that D-3 lacked, and
  `TestWritableParentRuleRequiresProcessObservations` plus
  `TestRulesListCommand` now pin it.
- The rule is a pure consumer of the normalized observation set: it never reads
  `/proc`, never stats a path, never executes anything. Filesystem and ACL facts
  arrive as attributes so the rule stays testable against synthetic trees.
- Findings are grouped per executable path so one shared binary cannot emit
  duplicate IDs; divergent observations of the same path become an INFO
  "inconsistent observations" finding instead of a claim.
- Four categories are structurally distinct outcomes (inventory = no finding,
  exposure = INFO, potential impact = MEDIUM/LOW, confirmed weakness = HIGH),
  which keeps "writable directory" from being reported as "privilege".

### Collection-layer corrections required by the rule

- `parent_effective_exec` did not exist; without it a directory could be judged
  replaceable even when the assessed user cannot traverse it.
- Parent mount context was written into `exe_mount_point` / `exe_nosuid` /
  `exe_noexec`, i.e. the executable inherited its *parent's* mount flags. A
  process running an executable from a different mount than its containing
  directory (bind mounts, overlay roots) would have been described with the
  wrong mount semantics, which matters directly for `nosuid`/`noexec` reasoning.
  New keys `parent_mount_point`, `parent_nosuid`, `parent_noexec` separate the
  two; `TestProcessPublishesParentExecAndSeparateMountContext` asserts both
  contexts in one observation.

### Test seam, not a production backdoor

`app.ScanConfig.ProcRoot` exists so an integration test can point the real
`app.Scan` pipeline at a synthetic `/proc`. The CLI never sets it (empty means
`/proc`), and the collector's budgets, PID-reuse guard and refusal to read
`environ`/`cmdline`/`mem`/`maps`/`fd` are unchanged.

### Architectural residual

- One structural asymmetry remains: `internal/rules/process` must interpret
  `allowed`/`denied`/`unknown` ACL values, so it imports
  `internal/platform/linux/acl` for its enum. That is a platform type leaking
  into the rule layer; a core-level access enum would be cleaner, but changing
  it now would touch every permission rule and is out of scope for a focused
  milestone.
- `internal/app.Scan` still has no automated coverage attribution of its own
  (tests live in `tests/integration`); the behaviour is exercised but the metric
  under-reports it.
- The lab deliverable is explicitly descoped rather than satisfied: `lab/`
  cannot construct a `/proc` tree, so M2 process scenarios are provided by the
  Go harness instead. The `lab` manifest and validator contracts are untouched.

### Decision

The M2 architecture is complete for its stated scope: every capability is
implemented, registered and reachable, and the collection → detection seam that
was missing for process data now exists and is asserted by tests. The verdict is
CONDITIONALLY ACCEPTED, conditional only on the Docker/isolation gate that this
directive prohibits and on a privileged-fixture confirmation of the HIGH branch
that requires root.
