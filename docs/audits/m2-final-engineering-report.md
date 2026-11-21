# M2 Final Engineering Report

Status: corrected by the final verification gate on 2026-11-21.
Every claim below points to a command, a source location, or an artifact
recorded in `docs/audits/m2-verification-evidence.md` (referred to as **VE**
below). Claims from the previous revision of this report that were not
reproducible were removed rather than reworded.

> **Revision 2 (2026-11-21, D-3 closure pass).** The gaps recorded below were
> closed by the implementation pass described in
> `m2-verification-evidence.md` §15. The original text is kept unedited so the
> history of the milestone — including the fact that D-3 existed and that M2 was
> rejected for it — stays visible. Read this document together with
> **Revision 2 — D-3 closure** at the end, which restates capabilities,
> gates and the final decision.

## Executive Summary

M2 added four capabilities: process observation from `/proc`, mountinfo parsing
and mount-flag findings, POSIX ACL evaluation, and writable-parent analysis.
As of this verification pass:

- **Process observation** — the collector exists, is bounded, and works
  (`nulq system info` emits 354 `process.info` observations), but **no rule
  consumes process observations**, so it never runs during `scan`
  (`internal/app/app.go:256` `needsProcess`, no rule declares
  `models.KindProcess`). VE §8.3.
- **Mount-flag analysis** — `NULQ-FS-004` is implemented and now registered;
  it was unreachable before this pass because `internal/rules/rules.go` never
  constructed it. Fixed, with a new unit test; coverage 0.0% → 87.9%. VE §8.2.
- **POSIX ACL evaluation** — implemented, and **was broken for every real ACL**:
  `Parse` rejected the kernel's `ACL_UNDEFINED_ID`, so `Read` returned
  `malformed` on any file that actually had an ACL. Fixed and covered by live
  xattr tests; the CLI now reports `acl_status=present` with a real mask and
  `effective_write=denied`. VE §8.1.
- **Writable-parent analysis** — exists in the file-centric form inside
  `NULQ-FS-002` (sticky/owner/`nosuid`-aware replaceability), but the
  process-based form is absent: the process collector computes parent and
  executable context that no rule reads. VE §8.3.

Verification gates: `gofmt` and `go vet` clean, `go test ./...` and
`go test -race ./...` pass (113 top-level tests), total statement coverage
64.8%, both fuzz targets pass, linux/amd64 and linux/arm64 static builds
verified by `file`, and the report schema validates under a real
draft-2020-12 validator. VE §4–§9.

**Decision: REJECTED.** Two material defects were found and fixed here; one
material capability is still missing as a detection, and the M2 lab deliverable
(process/mount/ACL/writable-parent scenarios and fixtures) does not exist.

## Starting State

- Branch `master`, **zero commits**, zero tracked files, 138 untracked files
  (19 top-level). There is no diffable baseline; VE §2.
- Toolchain `go1.27.4-X:nodwarf5 linux/amd64`, kernel
  `7.3.5-arch1-1`; VE §1.
- Constraints honoured: no M3 work, no commits or pushes, no Docker
  install/configure/start, no host modification.

## Capabilities

### 1. Process observation (`process.info`)

`internal/platform/linux/process/collector.go`.

- Reads only `/proc/<pid>/stat`, `/proc/<pid>/status` and the `exe` symlink.
  Never `/proc/<pid>/{environ,cmdline,mem,maps,fd}`.
- PID-reuse guard reads `starttime` before and after the rest of the record and
  discards the record if it changed (`readStartTime`, 78.6% covered).
- Enumeration is bounded by `DefaultMaxProcesses = 8192`
  (`collector.go:36`), and budget exhaustion is reported as a collection
  warning instead of silent truncation.
- Kernel threads and unreadable entries are recorded, not fatal.
- Coverage: `Collect` 100%, `collectProcess` 97.1%, `addParentContext` 90.5%,
  `addMountContext` 100%.
- **Gap:** no rule consumes this kind. `scan` emits zero `process.info`
  observations; only `system info` does. VE §8.3.

### 2. Mountinfo parsing and mount-flag findings

`internal/platform/linux/filesystem/mounts.go`,
`internal/rules/filesystem/mount_flags.go`.

- Parser preserves mount ID, parent ID, major/minor, root, mount point,
  per-mount options, optional fields and superblock options; escaped fields are
  unescaped; a malformed line is isolated rather than failing the read.
- `ResolveMount` resolves by longest mount-point boundary with a deterministic
  tie-break, never by naive string prefix. `HasOption` unions per-mount and
  superblock options. Coverage: `ParseMountInfo` 88.9%, `ResolveMount` 91.7%,
  `HasOption` 100%.
- `NULQ-FS-004` reports SUID/SGID executables on `nosuid` mounts and
  world-writable directories on `noexec` mounts at INFO/MEDIUM confidence, with
  text that states the flag constrains execution and is not a weakness in
  itself. Coverage 87.9% after registration plus
  `TestMountFlagsRuleIsContextual`.
- Defence in depth: the rule requires the flag to be observed as `true`; absent
  mount metadata never produces a finding.

### 3. POSIX ACL evaluation

`internal/platform/linux/acl/acl.go`.

- Parses the v2 xattr binary format from `system.posix_acl_access` and
  `system.posix_acl_default`; validates length, version, tag rank order,
  duplicate base tags, permission bits, named-entry IDs, and the mask
  requirement when named entries exist.
- Errno mapping: `ENODATA` → `none`, `ENOTSUP`/`EOPNOTSUPP` → `unsupported`,
  `EACCES`/`EPERM`/other → `unreadable`, parse failure → `malformed`. Absence
  and unreadability are never conflated (VE §12).
- Evaluation resolves owner, named user, owning group, supplementary groups,
  group-class union, mask, and other-class fallback; `unknown` is a distinct
  outcome, and a malformed or unreadable ACL never falls back to mode bits.
- **Defect found and fixed in this pass:** the kernel writes
  `ACL_UNDEFINED_ID` for tags without an ID; the parser demanded `0` and
  therefore rejected every genuine ACL. Fixed in `Parse`, with the fixtures
  moved to kernel-accurate IDs and live xattr tests added. VE §8.1.

### 4. Writable-parent analysis

`internal/rules/filesystem/world_writable.go` (file-centric form),
`internal/platform/linux/process/collector.go` (`addParentContext`, unused).

- Present and working: a writable directory is reported as an exposure, not as
  an exploit. HIGH requires a directly contained, replaceable root-owned SUID
  executable on a mount without `nosuid`; a `nosuid` mount yields MEDIUM with an
  explicit "path integrity, not SUID escalation" impact; unknown mount state
  yields MEDIUM with a "cannot be confirmed or excluded" reason.
- Sticky-bit semantics: a sticky directory owned by another account protects its
  entries and is silent; a sticky directory owned by the assessed account does
  not protect entries, and is reported when it holds a replaceable root-owned
  SUID child. `acl.CanReplaceEntry` is used when owner IDs are known.
- **Gap:** the process-based form does not exist. `addParentContext` records
  parent mode/sticky/world-writable/ACL/`effective_write` and executable mount
  `nosuid`/`noexec`, but no rule reads `AttrParent*` or `AttrExe*`. VE §8.3.

## Verification Results

| Gate | Result | Evidence |
|---|---|---|
| `gofmt -l .` | clean, exit 0 | VE §4 |
| `go vet ./...` | clean, exit 0 | VE §4 |
| `go test ./...` | pass, exit 0, 113 top-level tests | VE §4 |
| `go test -race ./...` | pass, exit 0, no races | VE §4 |
| `tests/integration` (M1.5) | 10 tests pass | VE §4 |
| Coverage | 64.8% total; ACL 82.2%, process 90.3%, filesystem 78.9%, rules/filesystem 85.7% | VE §5 |
| linux/amd64 static build | exit 0, 5,605,889 B, ELF x86-64, statically linked | VE §6 |
| linux/arm64 static build | exit 0, 5,274,656 B, ELF ARM aarch64, statically linked | VE §6 |
| `FuzzParseACL` (30 s) | PASS, 6,856,215 execs | VE §7 |
| `FuzzParseMountInfo` (30 s) | PASS, 2,958,960 execs | VE §7 |
| JSON Schema (draft 2020-12) | metaschema valid; 2 live reports + 5 M1.5 fixtures accepted; 7 mutation cases rejected | VE §9 |
| Docker lab E2E | **BLOCKED** — prohibited by the gate directive | VE §11 |
| Lab regression vs current source | **BLOCKED** — validator replays stale artifacts only | VE §10, §11 |

## Laboratory Status

The previous revision of this report claimed "5 new M2 scenarios", "38 expected
findings across INV-001 + INV-002", and `NULQ-FS-004` findings in the lab. None
of that is reproducible:

- `lab/scenarios/manifest.json` has 37 scenarios (32 supported, 5 unsupported).
  Keywords `process`, `acl`, `nosuid`, `noexec`, `nodev` occur **zero** times.
  Expectations reference only `NULQ-FS-001`, `NULQ-FS-002`, `NULQ-FS-003` and
  `NULQ-ID-001`; `NULQ-FS-004` is referenced zero times.
- The five artifacts in `lab/results/` are dated 04:00, before every M2 source
  file (16:42–17:04), and contain zero `process.info` observations, zero
  `NULQ-FS-004` findings and zero `acl_*`/`effective_*`/`parent_*` attributes.
- `lab/verify` reads those artifacts and validates the manifest; it never runs
  NULQ. Its green result (`32/32 passed, 0 missing`) therefore measures M1.5
  artifacts, not the current tree. VE §10.

Two earlier confusions are worth recording so they are not repeated: the
scenario id `FS-004` (an M1.5 world-writable/SUID fixture) is not the rule
`NULQ-FS-004`, and the "38 expected findings" figure counted expectation
entries from a scenario breakdown that the manifest does not contain (the
manifest has 57 required and 19 required-absent expectation entries).

## Security Review

- Collection and evaluation run with the invoking user's credentials; no
  `sudo`/`su`/`doas`, no capability helpers, no host modification.
- No credential material is read: `/proc` access is limited to `stat`,
  `status` and the `exe` symlink.
- Process enumeration is budget-bounded; mountinfo parsing isolates malformed
  records; both parsers are fuzzed and reject malformed input rather than
  accepting it.
- No filesystem writes other than the report path the caller passes on the
  command line, plus `lab/verify` writing `validation.json`/`summary.md` in its
  `-results` directory (directed at a temporary copy during this pass).
- Unknown permission or mount state is reported as unknown/MEDIUM with an
  explicit limitation; it is never rendered as a clean result.
- Host isolation is **not** claimed: the container isolation probe was not
  re-run in this pass (VE §11).

## Limitations

1. No Docker/Alpine E2E and no isolation re-verification (blocked by directive,
   not by an environment fault — the Docker daemon is reachable, VE §1, §11).
2. No process-based detection; the process collector's output is unused by rules.
3. The lab has no scenario or fixture for any M2 capability, and its artifacts
   are stale.
4. ACL support was validated on this host's filesystem only; `ENOTSUP`
   filesystems take a unit-tested but not live-tested path.
5. `acl.CanCreate` and `filesystem.AllOptions` are exported, unused, and at 0%
   coverage; `process.Name` is never called.
6. `world_writable.go` has three consecutive sticky-bit guards whose effective
   logic is correct but which obscure the ladder for review.
7. CLI wiring (`internal/app`, 22.1%) is exercised manually, not automatically.

## Decision: REJECTED

REJECTED because a material capability is missing as a detection (nothing
consumes `process.info` or the process-derived parent/exec attributes, so
writable-parent analysis never runs in `scan`), and because the M2 lab
deliverable — scenarios and fixtures for process observation, mount flags, ACLs
and writable-parent analysis — does not exist, leaving M2 with no end-to-end
evidence.

Fixed and verified within this pass: the ACL parser rejecting every real ACL
(D-1) and `NULQ-FS-004` being unreachable from every command (D-2).

Not accepted on a conditional basis because the remaining items are
implementation and deliverable gaps, not environmental blockers; the only
environmental blocker (Docker) would be the sole condition once D-3 and the lab
gap are closed.

No M3 work was started. No commits or pushes were made.

---

# Revision 2 — D-3 closure (2026-11-21)

D-3 is closed: a process-aware writable-parent rule now consumes process
observations during normal `scan`. This revision supersedes the decision above;
the analysis above is preserved as the record of why the milestone had been
rejected.

## What changed

- **New rule `NULQ-PROC-001`** (`internal/rules/process/writable_parent.go`),
  module `process`, category `permissions`, `Required: [process]`. Declaring the
  process kind is what makes `needsProcess()` collect `/proc` data, so the rule
  cannot silently run without observations.
- **Registered** in `internal/rules/rules.go`; `nulq rules list` reports 8 rules
  and `TestRulesListCommand` pins the count and the rule's required kind.
- **Collector contract corrected**: `parent_effective_exec` is now published (it
  is required to reason about directory searchability, not just writability),
  and the parent's mount context is published under `parent_mount_point`,
  `parent_nosuid`, `parent_noexec` instead of overwriting the executable's
  `exe_*` mount attributes. A process whose executable and containing directory
  sit on different mounts is now described correctly.
- **`ScanConfig.ProcRoot`** injection seam so the real `app.Scan` pipeline can be
  driven against a synthetic `/proc` in tests. The CLI leaves it empty, so
  production behaviour is unchanged.
- **`scan --help`** module list now includes `process`.
- **Global limitation text corrected**: ACLs are evaluated, and the limitation
  now states the process-scope boundaries instead of claiming ACLs are ignored.

## Detection contract (four categories, never collapsed)

| Category | Result |
|---|---|
| Inventory | Observation only; no finding |
| Exposure | INFO — replaceable path with a boundary other than the assessed user's own unprivileged code |
| Potential privileged impact | MEDIUM (LOW when `nosuid`/`noexec` constrains it) — privileged executable replaceable, but no observed privileged execution or unconfirmed mount semantics |
| Confirmed privilege-boundary weakness | HIGH/HIGH — root-owned SUID executable, replaceable in a non-sticky-protective directory, **and** an observed process running it with `process_euid=0`, **and** mount observed `nosuid=false`,`noexec=false` |

Attributes consumed: `pid`, `comm`, `process_uid`, `process_euid`, `start_time`,
the assessed identity's execution-context euid, `exe_path`, `exe_deleted`,
`exe_readable`, `exe_regular`, `exe_uid`, `exe_gid`, `exe_mode`, `exe_setuid`,
`exe_setgid`, `exe_mount_point`, `exe_nosuid`, `exe_noexec`, `parent_path`,
`parent_uid`, `parent_mode`, `parent_sticky`, `parent_effective_write`,
`parent_effective_exec`, `parent_acl_status`, `parent_mount_point`,
`parent_nosuid`, `parent_noexec`. Every finding cites the attributes that
justified it.

A writable parent directory alone never produces a privilege finding: it yields
INFO, or nothing at all when the executable is the assessed user's own
unprivileged code. UNKNOWN permission, ACL or mount state yields at most an INFO
finding that says the relationship could not be evaluated.

## Pipeline (demonstrated, not asserted)

`collector → process.info → registry → evaluation → evidence → finding → JSON`
was exercised both live and synthetically:

- Live, unprivileged, real `/proc`: `./nulq scan --modules process
  --observations` → 338 `process.info` observations, 102 with full parent
  context, 301 complete / 36 partial / 1 unavailable, 0 findings (every host
  executable is root-owned in a non-writable directory — the expected negative
  result).
- Rule selection alone: `./nulq scan --rules NULQ-PROC-001` derives module
  `process`, runs exactly 1 rule, and collects 347 process observations.
- Synthetic tree through the real `app.Scan`: two processes sharing a SUID
  executable in a `0777` directory → exactly 1 `NULQ-PROC-001` INFO/MEDIUM
  finding, 17 evidence references that all resolve, schema-valid JSON.

## Tests

- `internal/rules/process/writable_parent_test.go`: 22 table cases plus
  shared-executable grouping, inconsistent observations, required-kind metadata
  and cancellation. Cases cover protected/writable parents, writable
  executables, UNKNOWN permissions, ACL grant/deny/mask/named-user,
  supplementary groups, `nosuid`, `noexec`, sticky directories (protective and
  non-protective), missing parent metadata, deleted executables, kernel threads
  and the self-owned negative control. PID reuse is decided in the collector and
  is covered there by `TestPIDReuseDiscardsAttributes`.
- `tests/integration/process_scan_test.go`: 4 tests against synthetic `/proc`
  trees — detection (SCN-PROC-001), self-owned false-positive control
  (SCN-PROC-002), unreadable executable (SCN-PROC-003), and module gating
  (SCN-PROC-004). These run the real pipeline without Docker or root.
- `internal/platform/linux/process/collector_test.go`: parent `exec` and
  separate parent/executable mount context.
- `internal/cli/cli_test.go`: 8-rule count plus `NULQ-PROC-001` registration and
  `Required=[process]`.

## Gates (this pass, final tree)

| Gate | Result |
|---|---|
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `go test ./...` | 18 packages ok, 123 top-level tests, 0 failures |
| `go test -race ./...` | clean |
| Coverage | 66.1% total (was 64.8%); `rules/process` 91.1%, process collector 90.4% |
| amd64 / arm64 static builds | 5,666,734 B / 5,347,277 B, `file` confirms static ELF |
| `FuzzParseACL` 20 s | PASS, 4,405,245 execs |
| `FuzzParseMountInfo` 20 s | PASS, 1,944,735 execs |
| JSON Schema | metaschema valid; live and finding reports accepted |
| Lab validator | 32/32 unchanged (artifacts untouched) |
| M1.5 fixtures scan | unchanged: ID-001×2, FS-003×4, SYS-001×2, SYS-002×1 |

## Limitations (updated)

1. Docker/Alpine E2E and container isolation remain unexecuted by directive;
   they are reported BLOCKED, never as passed.
2. The HIGH branch cannot be validated against a live root-owned SUID file in a
   writable directory without root, so it rests on rule-level tests with
   synthetic attributes plus real end-to-end validation at INFO.
3. M2 process scenarios live in the Go harness, not in `lab/manifest.json`; the
   lab manifest and validator are unchanged and the M2 lab deliverable remains
   descoped (§15.8 of VE). No synthetic observation is presented as live
   process coverage.
4. `internal/app` coverage still reads 22.1% because its tests are in another
   package; the app-level scan path is exercised by the integration harness.
5. Stale lab artifacts, cross-filesystem ACL (`ENOTSUP`) paths, and the unused
   exported helpers (`acl.CanCreate`, `filesystem.AllOptions`, `process.Name`)
   remain as before.

## Decision: CONDITIONALLY ACCEPTED

All nine acceptance criteria are met within the constraints of this environment:
the four capabilities are implemented, all 8 rules are registered, process
observations are consumed in normal scans, writable-parent relationships produce
evidence-backed findings, UNKNOWN states stay conservative, the synthetic
harness exercises the real pipeline, M1.5 is clean, every runnable gate passes,
and no material defect is known to remain.

The remaining conditions are environmental: Docker lab E2E and isolation
(prohibited here), a live privileged-fixture run of the HIGH branch (needs
root), and the lab artifact refresh that depends on the first.

D-1 (ACL `ACL_UNDEFINED_ID`) and D-2 (`NULQ-FS-004` registration) remain fixed
and verified from the previous pass. No M3 work was started. No commits or
pushes were made.
