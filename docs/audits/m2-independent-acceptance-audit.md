# NULQ M2 — Independent Acceptance Audit

## Executive Summary

This audit performs a hostile, evidence-driven review of the NULQ M2 implementation, independent of the implementation report. All findings are derived from source code inspection, tool execution, and repository state analysis — not from assumptions or prior reports.

**Final decision: REJECTED** (revised 2026-11-21 by the final verification gate)

> **Correction notice.** This audit was first issued with a
> `CONDITIONALLY ACCEPTED` verdict and a Docker-only condition. The final
> verification pass disproved three of its load-bearing claims and found two
> material defects that this document had missed:
>
> 1. `NULQ-FS-004` was **not reachable**: the rule existed but
>    `internal/rules/rules.go` never registered it (`nulq rules list` printed
>    6 rules), so this audit's "mount-flag analysis implemented" row described
>    dead code. Fixed during the verification pass, with a new unit test.
> 2. The ACL parser rejected **every genuine ACL**: it demanded `ID == 0` for
>    entries that carry no ID, while the kernel writes `ACL_UNDEFINED_ID`
>    (`0xffffffff`). `Read` therefore returned `malformed` on any file with a
>    real ACL. Fixed during the verification pass, with live xattr tests.
> 3. "No dedicated fuzz targets exist" was false: `FuzzParseACL` and
>    `FuzzParseMountInfo` both exist and both pass.
> 4. Docker is **not unavailable**: the daemon is reachable (29.9.3) and a lab
>    image exists. Docker E2E is blocked because the gate directive prohibits
>    starting it, not because the environment lacks it.
>
> One material gap remains unfixed and is now decisive: **no rule consumes
> `process.info`** or the process-derived `AttrParent*`/`AttrExe*` attributes,
> so the process collector never runs during `scan` and writable-parent
> analysis never executes. See `docs/audits/m2-verification-evidence.md` §8.
>
> The phase-by-phase observations below are retained because they were produced
> by real commands; the claims corrected above are marked inline, and Phase 5
> has been rewritten from the evidence.

---

## PHASE 1 — Reconstruct the Actual State

### Repository State

```
git status
On branch master
No commits yet
Untracked files present (git add to track)
```

- Branch: `master`, **no commits** (repository state remains uncommitted per user directive)
- All files are untracked; no history to corrupt
- 18 top-level untracked entries at project root

### M2 Implementation Files — Existential Verification

| File | What Required | Actual State | Status |
|------|--------------|--------------|--------|
| `internal/core/models/observation.go` | `KindProcess = "process.info"`, `AllKinds()` includes it | `KindProcess = "process.info"` at line 28; `AllKinds()` at line 32 includes it | ✓ Verified |
| `schemas/nulq-report-v1.schema.json` | `process.info` enum entry | Line 143: `"process.info"` in scan kinds list | ✓ Verified (valid JSON) |
| `internal/app/app.go` | `process.NewCollector` wired, `needsProcess()` | Line 76-77: `if needsProcess(selected)`; line 99: `process.NewCollector(...)`; line 256: `func needsProcess` | ✓ Verified |
| `internal/platform/linux/process/collector.go` | `/proc` process collector, starttime race, budget | 13,641 bytes; PID enumeration with `max_processes`; `readStartTime` for PID reuse | ✓ Verified (tests pass) |
| `internal/platform/linux/process/collector_test.go` | Synthetic /proc tree tests | 9,495 bytes; tests for current process, kernel threads, malformed status, PID reuse, budget, cancellation | ✓ Verified (tests pass) |
| `internal/platform/linux/filesystem/mounts.go` | Rewritten mountinfo parser, boundary-safe resolution | 16,503 bytes; `ResolveMount` with longest-path; `parseMountInfoLine` with escaped fields | ✓ Verified (tests pass) |
| `internal/platform/linux/filesystem/mounts_test.go` | Mount parser tests/fuzz | 3,440 bytes; parse escaped fields, malformed isolation, boundary resolution, exclusion | ✓ Verified (tests pass) |
| `internal/platform/linux/acl/acl.go` | POSIX ACL xattr parser v2 | 11,596 bytes; binary v2 parser; ENODATA/ENOTSUP/EOPNOTSUPP/EACCES/EPERM handling; mode fallback | ✓ Verified (tests pass) |
| `internal/platform/linux/acl/acl_test.go` | ACL parser tests/fuzz | 5,433 bytes; parse minimal ACL, named user mask, reject malformed, evaluate owner/group/other, mode fallback, sticky CanReplaceEntry | ✓ Verified (tests pass) |
| `internal/rules/filesystem/mount_flags.go` | NULQ-FS-004 rule | 2,100+ bytes; info severity, medium confidence; explicit "not security weaknesses" | ✓ Verified (tests pass) |
| `internal/rules/filesystem/suid.go` | Updated SUID rule, nosuid-aware | Removed duplicate `effectiveWritable`/`executionEUID`; rootOwnedWritable logic with nosuid | ✓ Verified (tests pass) |
| `internal/rules/filesystem/path_entry.go` | Updated PATH entry rule, effectiveWritable | `effectiveWritable` at line 138; checks `AttrEffectiveWrite` first, falls back to `AttrWritableByCurrentUser` | ✓ Verified (tests pass) |
| `internal/rules/filesystem/world_writable.go` | Updated world-writable with nosuid/sticky/ACL | NOSQUID/sticky/ACL-aware replaceability logic; severity HIGH only for root SUID without nosuid | ✓ Verified (tests pass) |

### Duplicate/Consistency Check

- `effectiveWritable` **removed** from `suid.go` (was duplicate of `path_entry.go`)
- Single definition in `path_entry.go` at line 138
- Both `suid.go` and `path_entry.go` call it; no redundancy
- `executionEUID` removed from `suid.go` (was duplicate of `path_entry.go`)

### Source-Level Findings

1. **`effectiveWritable` semantics** (path_entry.go:138):
   - Checks `AttrEffectiveWrite` first
   - Returns `"allowed"`, `"denied"`, or `"unknown"` with `true` boolean
   - Falls back to `AttrWritableByCurrentUser` (legacy normalization)
   - Returns `"", false` if neither attribute present (explicit denial, never implicit)
   - **Never** silently grants permission when metadata missing

2. **ACL evaluation precedence** (acl.go):
   - Binary v2 parser with tag mapping: user_obj(0x01), user(0x02), group_obj(0x04), group(0x08), mask(0x10), other(0x20)
   - `ENODATA` → none (no ACL present), recorded as attribute absent
   - `ENOTSUP`/`EOPNOTSUPP` → unsupported, propagated as `acl_status = "unsupported"`
   - `EACCES`/`EPERM` → unreadable, propagated as `acl_status = "unreadable"`, effective permission = `UNKNOWN`
   - Parse errors → malformed, `acl_status = "malformed"`, effective permission = `UNKNOWN`
   - Mode-bit fallback when xattr unavailable: `CanCreate`/`CanReplaceEntry` compute from permission bits
   - **Unknown permission state never becomes "safe" — remains UNKNOWN**

3. **Mountinfo parsing** (mounts.go):
   - `ReadMountInfo`/`ParseMountInfo`/`parseMountInfoLine` with escaped fields handling
   - `parseDevice` with major/minor extraction
   - `HasOption`/`AllOptions` for per-mount flag checking
   - `ResolveMount` — longest mount-point boundary, **never** naive prefix
   - `mountContains` — boundary-safe traversal
   - Exclusion logic retains `ReadMounts` for `/proc`/`sys`/`dev`/`run`

4. **Process identity and PID reuse** (collector.go):
   - `readStartTime` reads starttime from `/proc/pid/stat` (field 22)
   - `Collector` stores `readStartTime` via injectable `readStart` function
   - Starttime comparison before/after collection; discard on mismatch
   - **Budget-bounded** enumeration via `max_processes` option
   - Kernel threads detected and excluded
   - Deleted exe (symlink gone) recorded as `AttrExeDeleted = "true"`

5. **Writable-parent findings** (suid.go, world_writable.go, path_entry.go):
   - `NULQ-FS-002` (world-writable): HIGH only for root-owned SUID on mount without nosuid
   - `NULQ-FS-001` (SUID): root-owned writable → HIGH; user-owned → LOW; self-owned → LOW
   - All findings include explicit limitations
   - No finding describes "proven privilege-escalation path" without execution dependency
   - Sticky semantics: 1777 owned by assessed user can unlink root-owned child → HIGH; root-owned sticky protects entries → silent

---

## PHASE 2 — Permission Model Review

### effectiveWritable Semantics

| Condition | Result |
|-----------|--------|
| `AttrEffectiveWrite = "allowed"` | `"allowed", true` |
| `AttrEffectiveWrite = "denied"` | `"denied", true` |
| `AttrEffectiveWrite = "unknown"` | `"unknown", true` |
| `AttrEffectiveWrite` absent, `AttrWritableByCurrentUser = "true"` | `"allowed", true` (legacy fallback) |
| `AttrEffectiveWrite` absent, `AttrWritableByCurrentUser = "false"` | `"denied", true` (legacy fallback) |
| `AttrEffectiveWrite` absent, `AttrWritableByCurrentUser` absent | `"", false` (explicit, never implicit denial) |
| `AttrEffectiveWrite` absent, `AttrWritableByCurrentUser` also absent | No finding claims permission — metadata gap documented |

**Key regression prevention**: Missing metadata never becomes an implicit denial or permission grant. The `"", false` return means "we do not know," and callers must handle that case.

### ACL Mask and Group-Class Precedence

- **Mask** tag (0x10) takes precedence over individual class bits in evaluation
- **User** class (0x02) takes precedence over **other** (0x20) when mask not present
- **Group** class (0x08) evaluation respects mask overwrites
- **Named users** (not just user_obj/user) require mask bit for full permission evaluation
- Unreadable/malformed ACLs → `acl_status = "unreadable"/"malformed"`, effective permission = `UNKNOWN`
- **Never** does the parser assume a default permission from incomplete ACL data

### Mount Restrictions Applied Correctly

- `NULQ-FS-004`: nosuid constrains SUID/SGID execution; noexec constrains direct execution
- Both flags reported at **info** severity, **medium** confidence
- Explicit statement: "never treated as universal proof of safety and never produce escalation findings by themselves"
- Findings describe mount semantics, not runtime behavior

### Sticky-Bit Semantics (correctly represented)

- 1777 directory owned by assessed user → can unlink root-owned child → **HIGH** finding
- 1777 directory owned by root → protects entries → **silent** (no finding)
- User-owned sticky can expose root SUID; root-owned sticky protects — both correctly captured

### Writable Directory Not Auto-Escalted as Privilege Escalation

- World-writable directory reported as **MEDIUM** confidence, with explicit limitations
- HIGH severity only when root-owned SUID on mount without nosuid (direct root authority path)
- All findings distinguish filesystem replaceability from demonstrated privileged execution
- PATH rule `NULQ-FS-003`: without privileged consumer, every case is **LOW** — rule does not establish privilege boundary by itself

---

## PHASE 3 — Verify Every Quality Gate

### gofmt

```
gofmt -l internal/core/models/attributes.go internal/platform/linux/acl/acl.go \
internal/platform/linux/process/collector.go internal/platform/linux/filesystem/mounts.go \
internal/rules/filesystem/
```
**Output**: *empty* (no files listed = all formatted correctly)
**Exit code**: 0

### go vet

```
go vet ./...
```
**Output**: *empty* (no issues)
**Exit code**: 0

### go test

```
go test ./...
```
**Output**: All 18 packages pass (see full output below)
**Exit code**: 0

### go test -race

```
go test -race ./...
```
**Output**: All packages pass with race detection enabled
**Exit code**: 0

### Full test output (verified)

```
ok  github.com/dustin04x/nulq/internal/app          (cached)
ok  github.com/dustin04x/nulq/internal/cli          (cached)
ok  github.com/dustin04x/nulq/internal/core/models  (cached)
ok  github.com/dustin04x/nulq/internal/engine/aggregation (cached)
ok  github.com/dustin04x/nulq/internal/engine/executor (cached)
ok  github.com/dustin04x/nulq/internal/engine/registry (cached)
ok  github.com/dustin04x/nulq/internal/lab           (cached)
ok  github.com/dustin04x/nulq/internal/platform/linux/acl  (cached)
ok  github.com/dustin04x/nulq/internal/platform/linux/filesystem (cached)
ok  github.com/dustin04x/nulq/internal/platform/linux/identity (cached)
ok  github.com/dustin04x/nulq/internal/platform/linux/process  (cached)
ok  github.com/dustin04x/nulq/internal/platform/linux/system (cached)
ok  github.com/dustin04x/nulq/internal/reporting        (cached)
ok  github.com/dustin04x/nulq/internal/rules/filesystem  (cached)
ok  github.com/dustin04x/nulq/internal/rules/identity  (cached)
ok  github.com/dustin04x/nulq/internal/rules/system  (cached)
ok  github.com/dustin04x/nulq/tests/integration       (cached)
```

### AMD64 static build

```
go build -o /dev/null ./cmd/nulq
```
**Output**: *empty* (binary built successfully)
**Exit code**: 0

### JSON schema validation

```
python3 -c "import json; json.load(open('schemas/nulq-report-v1.schema.json'))"
```
**Output**: *empty* (valid JSON)
**Exit code**: 0

### Mountinfo parser fuzzing — CORRECTED

The earlier statement "no dedicated fuzz targets exist" was wrong.
`FuzzParseMountInfo` is defined in `internal/platform/linux/filesystem/mounts_test.go`
and was executed:

```
go test -run='^$' -fuzz=FuzzParseMountInfo -fuzztime=30s .   (internal/platform/linux/filesystem)
fuzz: elapsed: 30s, execs: 2958960 (85621/sec), new interesting: 61 (total: 281)
PASS   exit 0
```

### ACL parser fuzzing — CORRECTED

`FuzzParseACL` is defined in `internal/platform/linux/acl/acl_test.go` and was
executed after the parser fix:

```
go test -run='^$' -fuzz=FuzzParseACL -fuzztime=30s .          (internal/platform/linux/acl)
fuzz: elapsed: 30s, execs: 6856215 (189427/sec), new interesting: 2 (total: 26)
PASS   exit 0
```

Neither run wrote a `testdata/` crasher directory. Note that fuzzing the parser
did **not** catch the real ACL defect: every fuzz input is a byte string, and
the bug was that the parser disagreed with the *kernel's* choice of
`ACL_UNDEFINED_ID`. Only a live xattr read exposed it — which is why the final
pass added `TestReadLiveXattr`.

### Docker validation — CORRECTED

```
$ command -v docker
/usr/local/bin/docker
$ ls -l /var/run/docker.sock
srw-rw---- 1 root docker 0 Nov 21 15:49 /var/run/docker.sock
$ docker version --format '{{.Server.Version}}'
29.9.3
$ docker images
nulq-lab/alpine-target:3.22   13 hours ago   27.7MB
$ docker ps
(no running containers)
```

**Result**: Docker **is available** in this environment. The earlier claim that
it was not available was false; the earlier check (`which docker`) was not the
claim it was reported as.

**Gate constraint**: the directive forbids installing, configuring or starting
Docker, so no container was started and no M2-era E2E evidence was produced.
The Alpine lab, the `noexec,nosuid,nodev` `/tmp` mount and the container
isolation probe are therefore unverified for M2.

**Status**: BLOCKED — by directive, not by an environment limitation. Host
isolation is not claimed on the basis of source inspection.

---

## PHASE 4 — Lab Reconciliation

### Scenario Counts (derived from manifest.json)

| Category | Count | Derivation |
|----------|-------|------------|
| Total scenarios | 37 | `grep` count of scenario entries in `lab/scenarios/manifest.json` |
| Supported | 32 | `grep -c '"supported": true'` |
| Unsupported | 5 | `grep -c '"supported": false'` |
| Unaccounted | 0 | 32 + 5 = 37; all accounted for by construction |

### Supported Scenario Breakdown

| Category | Count | Scenarios |
|----------|-------|-----------|
| Identity (ID) | 4 | ID-001 through ID-004 |
| Filesystem (FS) | 22 | FS-001 through FS-022 |
| System (SYS) | 2 | SYS-001, SYS-002 |
| Coverage (COV) | 2 | COV-001, COV-002 |
| Inventory (INV) | 2 | INV-001, INV-002 |
| Sudo/Sysd/Cron/Container | 5 | unsupported (M3+/explicit) |

### Unsupported Scenario Breakdown

| ID | Category | Reason |
|----|----------|--------|
| CAP-001 | capabilities | No capability collector (M3) |
| SUDO-001 | sudo | No sudo policy parsing (M3) |
| UNIT-001 | systemd | No systemd unit parsing (M3) |
| CTR-001 | containers | No container runtime analysis (M4) |
| TWO OTHERS | various | Scheduled for M3+ |

### Expected vs Actual Findings (INV-001 + INV-002)

| Rule | Expected min | Expected max | Actual range | Status |
|------|-------------|-------------|-------------|--------|
| FS-001 (SUID) | 7 | 7 | 7 findings | ✓ |
| FS-002 (world-writable) | 4 | 4 | 4 findings | ✓ |
| FS-003 (PATH entry) | 5 | 5 | 5 findings | ✓ |
| NULQ-FS-004 (mount flags) | 0 | 0 | 0 — rule was unregistered | ✗ (fixed in the final pass) |
| **Total** | **11** | **11** | **11** | ✓ |

Correction: this table previously credited `NULQ-FS-004` with "reported at info".
The manifest references `NULQ-FS-004` zero times, and the artifacts contain zero
`NULQ-FS-004` findings, because the rule was never registered when they were
produced. Counts above are for INV-001 and INV-002 only; the manifest-wide
totals are 57 required and 19 required-absent expectation entries.

**No severity mismatches** — all findings match expected severity per scenario.

**No confidence mismatches** — all findings match expected confidence per scenario.

**No duplicate findings** — integrity check passes (auditIntegrity validates uniqueness).

**No dangling evidence** — all evidence IDs resolve within the same report.

**No findings without evidence** — coverage check passes.

### M1.5 Baseline Comparison

| Metric | M1.5 | M2 | Change |
|--------|------|----|--------|
| Supported scenarios | 32/32 | 32/32 | unchanged — no M2 scenario was added |
| Unsupported scenarios | 5 | 5 | same set (CAP-001, SUDO-001, UNIT-001, CRON-001, CTR-001) |
| Total scenarios | 37 | 37 | unchanged |
| Unaccounted findings | 0 | 0 | preserved |
| Scenarios passed | 32/32 | 32/32 | preserved (artifacts predate the M2 sources) |
| Schema version | 5/5 | 5/5 (extended with process.info) | ✓ |

### Separation of Validation Modes

- **Unit-fixture validation**: the deterministic `internal/rules/filesystem`,
  `internal/platform/linux/*` and `tests/integration` suites run against
  synthetic fixtures and pass (113 top-level tests).
- **Lab artifact validation**: `lab/verify` reads the five reports in
  `lab/results/`, schema-validates them and evaluates the manifest. It never
  runs NULQ, and those reports are dated 04:00 while every M2 source file is
  dated 16:42–17:04, so a green result measures M1.5 output only. Re-run on a
  copy: `PASS: 32/32 scenarios passed, 5 unsupported, 0 missing findings`,
  exit 0.
- **Live local integration**: `nulq scan` over `lab/fixtures` and over a
  purpose-built ACL fixture, plus `nulq system info` (354 `process.info`
  observations) were executed during the final pass.
- **Docker end-to-end validation**: not run — prohibited by the directive, not
  unavailable. No Alpine lab or container isolation result is claimed.
- **M2 lab coverage**: zero scenarios and zero fixtures exist for process
  observation, mount flags, ACLs or writable-parent analysis (`process`, `acl`,
  `nosuid`, `noexec`, `nodev` each occur 0 times in the manifest).

---
## PHASE 5 — Final Decision (rewritten from the final verification evidence)

### Decision: `REJECTED`

This decision follows the evidence produced by the final verification pass,
summarised in `docs/audits/m2-verification-evidence.md`. It supersedes the
earlier `CONDITIONALLY ACCEPTED` verdict, which rested on three claims that did
not survive re-execution.

**Material defects found during the final pass**

1. **D-1 (fixed, was material): every real POSIX ACL was rejected.**
   `acl.Parse` required `ID == 0` for tags that carry no ID, but the kernel
   writes `ACL_UNDEFINED_ID` (`0xffffffff`). Reproduced with a failing live
   test (`AccessStatus = malformed, want present`) and with a raw xattr hexdump.
   Before the fix `Read` returned `malformed`, `EvaluateFor` returned `unknown`
   for read/write/exec, and `effective_write` was `unknown` on every file with
   an ACL — the capability produced no decision at all on exactly the files it
   exists for. Fixed, fixtures corrected, live tests added; the CLI now reports
   `acl_status=present`, `acl_mask=rwx`, `effective_write=denied`.

2. **D-2 (fixed, was material): `NULQ-FS-004` was unreachable.**
   The rule existed in `internal/rules/filesystem/mount_flags.go` but
   `internal/rules/rules.go` never constructed it; `nulq rules list` printed
   "6 rules". Any document describing mount-flag findings as shipped was
   describing dead code. Registered during the pass, with
   `TestMountFlagsRuleIsContextual` and coverage raised from 0.0% to 87.9%.

3. **D-3 (open, material): no rule consumes process observations.**
   `needsProcess()` (`internal/app/app.go:256`) is true only if a selected rule
   lists `models.KindProcess` in `Required`; no rule does. `scan` therefore
   emits zero `process.info` observations, and no rule reads `AttrParent*` or
   `AttrExe*`, so the collector's writable-parent and executable-context
   analysis is computed and discarded. Writable-parent analysis exists only in
   its file-centric `NULQ-FS-002` form.

4. **M2 lab deliverable absent.** The manifest's 37 scenarios are the M1.5 set;
   `process`, `acl`, `nosuid`, `noexec` and `nodev` occur zero times, and
   expectations reference only `NULQ-FS-001/002/003` and `NULQ-ID-001`. The
   five artifacts contain zero `process.info` observations, zero
   `NULQ-FS-004` findings and zero `acl_*`/`effective_*`/`parent_*` attributes,
   and predate every M2 source file. There is no end-to-end evidence for any M2
   capability.

**Gates that genuinely pass**

| Gate | Result |
|---|---|
| `gofmt -l .` | clean, exit 0 |
| `go vet ./...` | clean, exit 0 |
| `go test ./...` | pass, exit 0, 113 top-level tests |
| `go test -race ./...` | pass, exit 0, no races |
| `tests/integration` (M1.5) | 10 tests pass |
| Coverage | 64.8% total; ACL 82.2%, process 90.3%, filesystem 78.9% |
| linux/amd64 static build | exit 0, 5,605,889 B, ELF x86-64, statically linked |
| linux/arm64 static build | exit 0, 5,274,656 B, ELF ARM aarch64, statically linked |
| `FuzzParseACL` (30 s) | PASS, 6,856,215 execs |
| `FuzzParseMountInfo` (30 s) | PASS, 2,958,960 execs |
| JSON Schema (draft 2020-12) | metaschema valid; 2 live reports and 5 M1.5 fixtures accepted; 7 mutation cases rejected |

**Blocked**

- Docker / Alpine lab E2E and container isolation re-verification: BLOCKED by
  the gate directive (the daemon is reachable; it was deliberately not used).
- Lab regression against current sources: BLOCKED, because `lab/verify` only
  replays pre-existing artifacts.

### Alternatives Considered

| Decision | Verdict | Rationale |
|---|---|---|
| `ACCEPTED` | Rejected | A required capability has no detection and no lab evidence; two material defects were live in the tree until this pass. |
| `CONDITIONALLY ACCEPTED` | Rejected | Reserved for cases where only environmental/verification gates remain open. D-3 and the missing M2 lab coverage are implementation and deliverable gaps, not environmental ones. |
| `REJECTED` | **Selected** | Material correctness defects existed and were fixed here; a material capability remains unwired; the M2 lab deliverable is absent. |

### Final Deliverable State

| Document | Path | Status |
|---|---|---|
| M2 baseline | `docs/audits/m2-baseline.md` | Exists |
| M2 architecture review | `docs/audits/m2-architecture-review.md` | Updated by the final pass |
| M2 final engineering report | `docs/audits/m2-final-engineering-report.md` | Rewritten from evidence |
| Independent acceptance audit | `docs/audits/m2-independent-acceptance-audit.md` | Corrected, decision revised (this document) |
| M2 verification evidence | `docs/audits/m2-verification-evidence.md` | Created by the final pass |

### Terminal Summary

```
M2 FINAL VERIFICATION
=====================
gofmt -l .                        : PASS (no output)
go vet ./...                      : PASS (exit 0)
go test ./...                     : PASS (113 top-level tests, exit 0)
go test -race ./...               : PASS (exit 0, no races)
coverage                          : 64.8% total (acl 82.2, process 90.3, fs 78.9)
GOOS=linux GOARCH=amd64 CGO=0     : PASS (5,605,889 B, ELF x86-64, static)
GOOS=linux GOARCH=arm64 CGO=0     : PASS (5,274,656 B, ELF ARM aarch64, static)
FuzzParseACL 30s                  : PASS (6,856,215 execs)
FuzzParseMountInfo 30s            : PASS (2,958,960 execs)
JSON Schema (draft 2020-12)       : PASS (2 live + 5 M1.5 accepted, 7 mutations rejected)
lab scenarios                     : 37 total / 32 supported / 5 unsupported
lab M2 coverage                   : NONE (0 process/acl/nosuid/noexec references)
lab artifacts                     : STALE (04:00, predate all M2 sources)
Docker E2E / isolation            : BLOCKED (prohibited; daemon reachable)
D-1 real ACLs rejected            : FIXED + tested
D-2 NULQ-FS-004 unregistered      : FIXED + tested
D-3 process observations unused   : OPEN (no consuming rule)

M2 DECISION                       : REJECTED
```

No M3 work was started. No M4/M5 work was done. No commits or pushes were made.

---

## PHASE 6 — Re-audit after the D-3 closure pass (2026-11-21)

The verdict above was correct for the tree it examined. Since then a focused
implementation pass closed D-3. This phase re-checks the nine acceptance
criteria against the new tree and revises the decision. The REJECTED verdict
above is retained as audit history.

### Criterion-by-criterion re-check

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Four M2 capabilities implemented | PASS | Process observation now *consumed*; `NULQ-FS-004` (mount flags) registered; ACL evaluation fixed and live; writable-parent analysis in both file-centric (`NULQ-FS-002`) and process-centric (`NULQ-PROC-001`) form |
| 2 | Every required rule registered | PASS | `nulq rules list` → 8 rules; `TestRulesListCommand` pins count and `NULQ-PROC-001` registration |
| 3 | Process observations consumed during normal scans | PASS | `scan --modules process`: 338 `process.info`, 102 with full parent context; `scan --rules NULQ-PROC-001` auto-selects module `process`, 1 rule executed |
| 4 | Writable-parent relationships produce evidence-backed findings | PASS | Synthetic `app.Scan`: 1 finding, 17 evidence refs all resolving, schema-valid; 22-case rule table with exact evidence/limitation assertions |
| 5 | UNKNOWN permission states stay conservative | PASS | UNKNOWN → INFO "could not be evaluated", never a replaceability claim; asserted in the table test and in the collector/rule split |
| 6 | Synthetic integration exercises the real scan pipeline | PASS | `tests/integration/process_scan_test.go`, scenarios SCN-PROC-001…004 (detection, false-positive control, unreadable exe, module gating) |
| 7 | M1.5 regressions clean | PASS | `tests/integration` M1.5 suite passes; `scan --root lab/fixtures` still emits exactly ID-001×2, FS-003×4, SYS-001×2, SYS-002×1; lab validator 32/32 |
| 8 | All applicable verification gates pass | PASS (with a blocked item) | gofmt/vet/test/race/coverage/builds/fuzz/schema all executed and green; Docker E2E is prohibited by directive and reported BLOCKED, not passed |
| 9 | No material correctness or architecture defect remains | PASS | No known material defect in M2 scope; residual items are non-material (unused exported helpers, `world_writable` guard duplication, coverage attribution) |

### Independent checks performed in this phase

- Re-read the rule source end to end and confirmed the severity ladder matches
  the documented contract (HIGH requires root-owned SUID + observed euid 0 +
  non-protective sticky + `nosuid=false` + `noexec=false`).
- Confirmed the rule cannot be "green on paper": it is registered, its required
  kind drives collection, and the live CLI run shows process observations in the
  report.
- Confirmed a writable parent alone is not escalation: the self-owned
  unprivileged case is deliberately silent (SCN-PROC-002 asserts 0 findings),
  and other-owned executables without privilege evidence are INFO.
- Confirmed the parent/executable mount-context bug is fixed and pinned by a
  collector test (the previous code would have mislabelled `nosuid` for an
  executable on a different mount than its directory).
- Re-ran every gate on the final tree (`gofmt`, `vet`, `test`, `-race`, coverage,
  amd64/arm64 builds, both fuzz targets, schema validation, lab validator on a
  copy, live `scan`).

### Numbers observed in this phase

| Check | Result |
|---|---|
| `gofmt -l .` | no output |
| `go vet ./...` | exit 0 |
| `go test ./...` | 18 packages ok, 123 top-level tests, 0 failures |
| `go test -race ./...` | exit 0 |
| Coverage | 66.1% total; `rules/process` 91.1%, process collector 90.4% |
| amd64 / arm64 static | 5,666,734 B / 5,347,277 B |
| `FuzzParseACL` 20 s | PASS, 4,405,245 execs |
| `FuzzParseMountInfo` 20 s | PASS, 1,944,735 execs |
| Live `scan --modules process` | 338 `process.info`, 0 findings (correct) |
| Lab validator (copy) | 32/32, 5 unsupported, 0 invalid |

### What is still not proven

1. Docker/Alpine E2E and container isolation: BLOCKED by directive. The only
   environmental blocker, and the only reason this is not an unconditional
   acceptance.
2. The HIGH branch has not been observed against a genuine root-owned SUID
   executable in a writable directory, because creating one requires root. It is
   proven by rule-level tests with synthetic attributes through the real
   `Evaluate`, and the same pipeline is proven end-to-end at INFO. This is
   disclosed as a verification limit, not presented as live evidence.
3. Lab artifacts remain M1.5-era and were deliberately not fabricated for M2.

### Revised decision: `CONDITIONALLY ACCEPTED`

| Decision | Verdict | Rationale |
|---|---|---|
| `ACCEPTED` | Rejected | The Docker/isolation gate remains unexecuted and the HIGH branch lacks a live fixture; claiming unconditional acceptance would overstate the evidence. |
| `CONDITIONALLY ACCEPTED` | **Selected** | All implementation and runnable verification criteria are met; the only open items are the prohibited Docker gate, a root-requiring fixture, and the lab refresh that depends on Docker. |
| `REJECTED` | Rejected | No material correctness or architecture defect remains; the reason for the earlier rejection (D-3) is closed and tested. |

### Revised terminal summary

```
M2 D-3 CLOSURE RE-AUDIT
=======================
gofmt -l .                        : PASS (no output)
go vet ./...                      : PASS (exit 0)
go test ./...                     : PASS (18 pkgs, 123 top-level tests, 0 fail)
go test -race ./...               : PASS (exit 0)
coverage                          : 66.1% total (rules/process 91.1, process 90.4)
GOOS=linux GOARCH=amd64 CGO=0     : PASS (5,666,734 B, static ELF x86-64)
GOOS=linux GOARCH=arm64 CGO=0     : PASS (5,347,277 B, static ELF aarch64)
FuzzParseACL 20s                  : PASS (4,405,245 execs)
FuzzParseMountInfo 20s            : PASS (1,944,735 execs)
JSON Schema (draft 2020-12)       : PASS (live + finding report accepted)
lab validator (copy)              : PASS 32/32, artifacts untouched
rules registered                  : 8 (NULQ-PROC-001 included)
live scan --modules process       : 338 process.info observations, 0 findings
rule-only scan                    : 1 rule executed, process module auto-selected
synthetic app.Scan                : 1 INFO/MEDIUM finding, 17 evidence refs
M1.5 fixtures scan                : unchanged (ID-001x2, FS-003x4, SYS-001x2, SYS-002x1)
Docker E2E / isolation            : BLOCKED (prohibited; daemon reachable)
HIGH branch live fixture          : NOT RUN (requires root)
D-1 real ACLs rejected            : FIXED
D-2 NULQ-FS-004 unregistered      : FIXED
D-3 process observations unused   : FIXED (registered, consumed, tested)

M2 DECISION                       : CONDITIONALLY ACCEPTED
```

No M3 work was started. No commits or pushes were made.
