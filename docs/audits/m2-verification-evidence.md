# M2 Verification Evidence

Verification date: 2026-11-21.
Scope: NULQ M2 (process observation, mountinfo parsing, POSIX ACL evaluation,
writable-parent analysis). No M3 work, no commits, no pushes, no host changes.

This document records only commands that were actually executed during this
verification pass, their exit codes, and captured excerpts of their output.
Where a check could not be executed it is recorded as **BLOCKED** with the
reason. No result in this document is inferred from a previous audit.

---

## 1. Environment

| Item | Value | How obtained |
|---|---|---|
| Go toolchain | `go1.27.4-X:nodwarf5 linux/amd64` | `go version` |
| Default target | `GOOS=linux GOARCH=amd64 CGO_ENABLED=1` | `go env GOOS GOARCH CGO_ENABLED` |
| Kernel | `Linux 7.3.5-arch1-1 x86_64` | `uname -srm` |
| JSON Schema validator | `jsonschema` Python 4.26.0 (Draft 2020-12) | imported in the validation script |
| Docker CLI / daemon | `/usr/local/bin/docker`, daemon `29.9.3` reachable | `docker version --format '{{.Server.Version}}'` |
| Running containers | none | `docker ps` |

The Docker daemon is reachable and a `nulq-lab/alpine-target:3.22` image from a
prior run exists. The gate directive forbids installing, configuring or starting
Docker, so no container was started. See §9.

## 2. Repository state (unchanged by this pass)

```
$ git rev-parse --abbrev-ref HEAD
master
$ git log --oneline -3
fatal: your current branch 'master' does not have any commits yet
$ git ls-files | wc -l
0
$ git status --porcelain | grep -c '^??'      # top-level untracked entries
19
$ git status --porcelain -uall | grep -c '^??' # recursive untracked files
138
$ git status --porcelain | grep -c '^ M'
0
```

The repository has no commits and no tracked files; everything is untracked
working-tree content. There is therefore no `git diff` to review and no
baseline to regress against other than the M1.5 lab artifacts and documents.

## 3. Source inventory

| Responsibility | File(s) |
|---|---|
| Process collection | `internal/platform/linux/process/collector.go` |
| Mountinfo parsing and resolution | `internal/platform/linux/filesystem/mounts.go` |
| POSIX ACL parsing and evaluation | `internal/platform/linux/acl/acl.go` |
| Effective writability | `internal/platform/linux/acl/acl.go` (`EvaluateFor`), `internal/platform/linux/filesystem/collector.go` (`applyPermissions`), `internal/rules/filesystem/path_entry.go` (`effectiveWritable`) |
| Writable-parent detection | `internal/rules/filesystem/world_writable.go` (path-entry replaceability); `internal/platform/linux/process/collector.go` (`addParentContext`, produces attributes **consumed by no rule**) |
| Mount-flag findings | `internal/rules/filesystem/mount_flags.go` (`NULQ-FS-004`), registered in `internal/rules/rules.go` |
| Severity and confidence | `internal/core/models/finding.go`, per-rule severity ladders in `internal/rules/filesystem/*.go` |
| Evidence generation | `internal/evidence/`, `internal/core/models/finding.go` (`Validate`) |
| Lab validation | `internal/lab/{manifest,schema,validate,summary}.go`, `lab/verify/main.go` |

## 4. Regression and quality gates

All commands were run from the repository root.

```
$ gofmt -l .
(no output)                                    exit 0
$ go vet ./...
(no output)                                    exit 0
$ go test ./...
ok  github.com/dustin04x/nulq/internal/app
ok  github.com/dustin04x/nulq/internal/cli
ok  github.com/dustin04x/nulq/internal/core/models
ok  github.com/dustin04x/nulq/internal/engine/aggregation
ok  github.com/dustin04x/nulq/internal/engine/executor
ok  github.com/dustin04x/nulq/internal/engine/registry
ok  github.com/dustin04x/nulq/internal/lab
ok  github.com/dustin04x/nulq/internal/platform/linux/acl
ok  github.com/dustin04x/nulq/internal/platform/linux/filesystem
ok  github.com/dustin04x/nulq/internal/platform/linux/identity
ok  github.com/dustin04x/nulq/internal/platform/linux/process
ok  github.com/dustin04x/nulq/internal/platform/linux/system
ok  github.com/dustin04x/nulq/internal/reporting
ok  github.com/dustin04x/nulq/internal/rules/filesystem
ok  github.com/dustin04x/nulq/internal/rules/identity
ok  github.com/dustin04x/nulq/internal/rules/system
ok  github.com/dustin04x/nulq/tests/integration
(?  → packages with no test files: cmd/nulq, core/errors, core/interfaces,
   engine/store, evidence, rules, version, lab/verify, pkg/api)
                                               exit 0
$ go test -race ./...
(no non-`ok` lines)                            exit 0
```

Passing top-level tests: `113` (`go test ./... -v | grep -c '^--- PASS'`).

M1.5 integration suite run independently:

```
$ go test ./tests/integration/ -v | grep -c '^--- PASS'
10                                             exit 0
```

No test was skipped, weakened or rewritten. Two existing test expectations were
updated as a direct consequence of the defect fixes in §8 (`TestRulesListCommand`
expected rule count, and the ACL blob fixtures now use the kernel's
`ACL_UNDEFINED_ID`); both changes make the tests stricter, not looser.

## 5. Coverage

```
$ go test -coverprofile=/tmp/nulq-m2-coverage.out ./...
$ go tool cover -func=/tmp/nulq-m2-coverage.out | tail -1
total:  (statements)  64.8%                     exit 0
```

Package level:

| Package | Coverage |
|---|---|
| internal/engine/aggregation | 93.3% |
| internal/rules/identity | 95.7% |
| internal/rules/system | 95.1% |
| internal/rules/filesystem | 85.7% |
| internal/platform/linux/process | 90.3% |
| internal/platform/linux/identity | 87.3% |
| internal/platform/linux/acl | 82.2% |
| internal/platform/linux/filesystem | 78.9% |
| internal/platform/linux/system | 67.6% |
| internal/reporting | 63.2% |
| internal/cli | 55.2% |
| internal/lab | 53.2% |
| internal/core/models | 47.1% |
| internal/app | 22.1% |
| internal/evidence, engine/store, rules, lab/verify, pkg/api, cmd/nulq | 0.0% |

Security-critical functions:

| Function | Coverage |
|---|---|
| `acl.EvaluateFor` | 100.0% |
| `acl.PermText`, `acl.permFromBits`, `acl.groupMatch` | 100.0% |
| `acl.Read` | 90.0% |
| `acl.Parse` | 85.7% |
| `acl.readOne` (errno mapping) | 63.2% |
| `acl.CanReplaceEntry` | 83.3% |
| `acl.CanCreate` | **0.0%** (exported, called from nowhere — dead code) |
| `filesystem.ParseMountInfo` | 88.9% |
| `filesystem.ResolveMount` | 91.7% |
| `filesystem.HasOption` | 100.0% |
| `filesystem.AllOptions` | **0.0%** (exported, unused) |
| `process.Collect` | 100.0% |
| `process.collectProcess` | 97.1% |
| `process.addParentContext` | 90.5% |
| `process.addMountContext` | 100.0% |
| `NULQ-FS-004 Evaluate` (`mount_flags.go`) | 87.9% |
| `NULQ-FS-001 Evaluate` (`suid.go`) | 88.4% |
| `NULQ-FS-002 Evaluate` (`world_writable.go`) | 84.3% |
| `NULQ-FS-003 Evaluate` (`path_entry.go`) | 97.6% |
| `effectiveWritable` | 90.9% |

Untested branches that matter: `acl.readOne`'s `ERANGE` retry path and the
`size <= 0` guard, `acl.CanCreate`, `filesystem.AllOptions`, and
`process.Name`.

Coverage adequacy for security-critical code: the decision core
(`EvaluateFor`, permission masking, group-class union, mount resolution,
mounting-option union) is at 88–100%. The remaining uncovered statements are
either unreachable through the CLI (`CanCreate`, `AllOptions`), or defensive
paths that would require a synthetic syscall failure (`ERANGE`) to reach. That
is adequate for M2 *given* the process-collection integration gap in §8.3, which
no amount of unit coverage would have disclosed.

## 6. Cross-compilation

```
$ GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/nulq-m2-amd64 ./cmd/nulq
exit 0
$ ls -l /tmp/nulq-m2-amd64   → 5605889 bytes
$ file /tmp/nulq-m2-amd64
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info

$ GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/nulq-m2-arm64 ./cmd/nulq
exit 0
$ ls -l /tmp/nulq-m2-arm64   → 5274656 bytes
$ file /tmp/nulq-m2-arm64
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info
```

No `//go:build` incompatibility surfaced. Both targets produce genuinely static
binaries (`CGO_ENABLED=0`), verified by `file`, not assumed from the exit code.

## 7. Fuzzing

Two fuzz targets exist and both were executed after the ACL parser change.

```
$ cd internal/platform/linux/acl
$ go test -run='^$' -fuzz=FuzzParseACL -fuzztime=30s .
fuzz: elapsed: 30s, execs: 6856215 (189427/sec), new interesting: 2 (total: 26)
PASS                                            exit 0
ok  github.com/dustin04x/nulq/internal/platform/linux/acl   30.107s

$ cd internal/platform/linux/filesystem
$ go test -run='^$' -fuzz=FuzzParseMountInfo -fuzztime=30s .
fuzz: elapsed: 30s, execs: 2958960 (85621/sec), new interesting: 61 (total: 281)
PASS                                            exit 0
ok  github.com/dustin04x/nulq/internal/platform/linux/filesystem   30.106s
```

- Targets: `FuzzParseACL` (`acl_test.go`), `FuzzParseMountInfo` (`mounts_test.go`).
- No crashes, no hangs, no failures; `git status` shows no `testdata/` directory
  written by either run, so no input was promoted to a regression corpus.
- Both targets feed arbitrary bytes into the parsers, which validate size,
  version, tag order, entry count, permission bits and ID rules before
  accepting anything; malformed input returns an error rather than a permissive
  ACL (asserted by `TestParseRejectsMalformedAndUnsupported`).
- Fuzz coverage of the *xattr read* path is indirect: the parser is fuzzed, the
  syscall wrapper is covered by the live tests in §8.1.

## 8. Defects found, reproduced, and fixed in this pass

Both defects were reproduced with a failing test before any implementation
change, per the gate rules.

### 8.1 D-1 (material): every real POSIX ACL was rejected as `malformed`

Reproduction (`TestReadLiveXattr`, a real directory with a real
`system.posix_acl_access` xattr written by the kernel):

The first attempt used a minimal ACL equivalent to the file mode, which the
kernel discards (`posix_acl_update_mode`), so absence was reported correctly.
The second attempt used a named-user ACL that the kernel really stores:

```
--- FAIL: TestReadLiveXattr
    acl_test.go:180: AccessStatus = malformed, want present
```

Raw kernel bytes for the same ACL, dumped from a probe:

```
probe size=44 err=<nil>
hex=0200000001000700ffffffff02000600e903000004000500ffffffff10000600ffffffff20000400ffffffff
parse err=base ACL tag 0x01 has non-zero ID   text=""
```

Cause: the kernel writes `ACL_UNDEFINED_ID` (`0xffffffff`) in the ID field of
entries that carry no numeric ID (owner, owning group, mask, other). `Parse`
required those IDs to be exactly `0`, and every unit fixture had been
hand-built with `0`, so the parser passed its tests while rejecting 100% of
genuine ACLs. Consequence before the fix: `Read` returned `malformed`,
`EvaluateFor` returned `unknown` for read/write/exec, and
`applyPermissions` recorded `effective_write=unknown` — the ACL capability
produced no decision at all on any file that actually had an ACL.

Fix (`internal/platform/linux/acl/acl.go`): accept `0` or `undefinedID` for
tags without an ID and normalize to `0`; reject `undefinedID` for named
user/group entries. Test fixtures now emit `ACL_UNDEFINED_ID` so the
regression cannot hide again.

After the fix, end-to-end through the CLI (a SUID file carrying a real ACL with
`u::r-x` for the owner and `u:1001:rwx` named user):

```
$ ./nulq scan --root /tmp/aclfix --format json --observations --output /tmp/aclfix2-obs.json
exit 0
filesystem.file /tmp/aclfix/bin/tool
    acl_access = u::r-x,u:1001:rwx,g::r-x,m::rwx,o::r-x
    acl_status = present
    acl_mask = rwx
    effective_exec = allowed
    effective_write = denied
    writable_by_current_user = false
```

Tests added: `TestReadLiveXattr` (xattr read + mask extraction + ACL precedence
over mode 0777), `TestReadAbsentACLIsNotUnreadable` (absence ≠ unreadable),
`TestReadUnreadablePathStaysUnknown` (ENOENT → `unreadable` → `unknown`).

### 8.2 D-2 (material): `NULQ-FS-004` was implemented but never registered

```
$ ./nulq rules list
7 rules. Use `nulq rules list --format json` for full metadata.
   (before the fix: "6 rules", and NULQ-FS-004 absent from the table)
```

`internal/rules/filesystem/mount_flags.go` existed, was listed in the M2 audit
documents as an active capability, had 0.0% coverage, and was unreachable from
any command because `internal/rules/rules.go` never constructed it.

Fix: register `fsrules.NewMountFlagsRule()`; update
`TestRulesListCommand`'s expected count from 6 to 7; add
`TestMountFlagsRuleIsContextual` covering SUID-on-`nosuid` (1 INFO),
SUID on a mount without `nosuid` (0), world-writable dir on `noexec` (1 INFO)
and on a mount without `noexec` (0), asserting evidence is cited and each
finding validates. Coverage went from 0.0% to 87.9%.

### 8.3 D-3 (material, NOT fixed): no rule consumes process observations

```
$ grep -rn 'KindProcess' --include='*.go' internal/ | grep -vE 'core/models|platform/linux/process|internal/evidence'
internal/app/app.go:259:            if kind == models.KindProcess {
$ grep -rn 'KindProcess' --include='*.go' internal/rules/
(none)
$ grep -rn 'AttrExeMountPoint|AttrExeNosuid|AttrExeNoexec|AttrParentEffectiveWrite|AttrParentACL' --include='*.go' internal/rules/
(no rule consumes process-derived attributes)
```

`needsProcess()` (`internal/app/app.go:256`) returns true only when a selected
rule lists `models.KindProcess` in `Required`. No rule does, so the process
collector never runs during `scan`. Confirmed at runtime:

```
$ ./nulq system info --format json --output /tmp/v-sysinfo.json   → exit 0, 354 process.info observations
$ ./nulq scan --root lab/fixtures --format json --observations --output /tmp/nulq-scan-obs.json
  → filesystem.mount, filesystem.path_entry, filesystem.scan, system.*, identity.* only; 0 process.info
```

The process collector computes parent-directory writability, parent ACL state,
parent mount `nosuid`/`noexec`, and an `executable_*` context, but no rule reads
any of `AttrParent*` or `AttrExe*`. The "writable-parent relationship analysis"
capability is therefore implemented as *collection* and absent as *detection*.
This is a missing detection rule, not a wiring bug, so it is reported rather
than written during a verification pass.

**Status: FIXED in the D-3 closure pass. See §15.** The text above is retained
as the evidence that the original M2 implementation was incomplete.

### 8.4 Non-blocking debt

- `acl.CanCreate` is exported and called from nowhere (0.0% coverage).
- `filesystem.AllOptions` is exported and called from nowhere (0.0% coverage).
- `process.Name` is never called (0.0% coverage).
- `world_writable.go` contains three consecutive, partly redundant sticky-bit
  guards (lines ~89–101); the effective logic is correct but the duplication
  makes the ladder harder to audit.

## 9. JSON Schema validation

Draft declared by the schema: `https://json-schema.org/draft/2020-12/schema`.
Validator: `jsonschema` 4.26.0 `Draft202012Validator` (a real draft-2020-12
validator, not a JSON syntax check).

```
metaschema check_schema ................ VALID
live system info report ................ ACCEPTED   (354 process.info observations)
live scan report (findings) ............ ACCEPTED
wrong schema_version ('9.9') ........... REJECTED   '1.1' was expected at ['schema_version']
missing 'coverage' ..................... REJECTED   'coverage' is a required property
severity 'SEVERE' ...................... REJECTED   not one of [INFO, LOW, MEDIUM, HIGH, CRITICAL]
confidence 'certain' ................... REJECTED   not one of [LOW, MEDIUM, HIGH]
empty evidence list .................... REJECTED   [] should be non-empty
empty rule_id .......................... REJECTED   '' should be non-empty
unknown observation kind 'process.unknown'  REJECTED   not one of [...]
M1.5 fixtures (5 files) ................ ACCEPTED  ×5  (schema_version 1.1)
```

Note on method: `severity: "CRITICAL"` was tried first as an "invalid" value and
was **accepted**, because the schema legitimately enumerates `CRITICAL`. The
rejection case was re-run with `SEVERE`. Recording this because the earlier
audit claimed a rejection that the value used could not have produced.

The five M1.5 artifacts in `lab/results/` still validate under schema_version
1.1, so the schema change is backward compatible.

## 10. Lab reconciliation (derived programmatically from the files)

Manifest `lab/scenarios/manifest.json`:

- Total scenarios: **37**
- Supported: **32**; unsupported: **5** (`CAP-001`, `SUDO-001`, `UNIT-001`,
  `CRON-001`, `CTR-001`)
- By category: filesystem 7, path-hijack 7, suid-sgid 6, coverage 6, identity 4,
  system 2, capabilities 1, sudo 1, systemd 1, cron 1, containers 1
- Expectation entries across supported scenarios: **57** required findings,
  **19** required-absent findings, **9** observation assertions, 0 runtime
  assertions
- Every supported scenario has a non-empty `expect` block
- Rule IDs referenced by expectations: `NULQ-FS-002` 32, `NULQ-FS-001` 29,
  `NULQ-FS-003` 13, `NULQ-ID-001` 2. **`NULQ-FS-004`: 0.**
- Keyword occurrences in the manifest: `process` 0, `acl` 0, `nosuid` 0,
  `noexec` 0, `nodev` 0.

Artifacts in `lab/results/`:

| Artifact | mtime | schema_version | observations | findings | process.info | NULQ-FS-004 |
|---|---|---|---|---|---|---|
| scan.json | 11-21 04:00 | 1.1 | 50 | 6 | 0 | 0 |
| scan-fixtures.json | 11-21 04:00 | 1.1 | 64 | 21 | 0 | 0 |
| scan-path.json | 11-21 04:00 | 1.1 | 67 | 25 | 0 | 0 |
| scan-identity.json | 11-21 04:00 | 1.1 | 17 | 1 | 0 | 0 |
| scan-discovery.json | 11-21 04:00 | 1.1 | 56 | 1 | 0 | 0 |

The artifacts contain **zero** `acl_*`, `effective_*`, `parent_*` or `exe_*`
attributes. The M2 sources (`internal/rules/rules.go` 17:03,
`internal/platform/linux/acl/acl.go` 17:04, `process/collector.go` 16:42,
`mount_flags.go` 16:42) are all newer than every artifact (04:00). The
artifacts are M1.5-era output.

Validator behaviour: `lab/verify/main.go` reads `lab/results/*.json`, validates
each against the schema and evaluates the manifest expectations
(`internal/lab/validate.go`). It never invokes NULQ, so it cannot detect a
regression in collection or rule wiring — only in artifacts that were produced
by someone else.

Running the validator against a copy (so the committed artifacts are not
rewritten):

```
$ cp -r lab/results /tmp/labres
$ go run ./lab/verify -results /tmp/labres -manifest lab/scenarios/manifest.json -schema schemas/nulq-report-v1.schema.json
PASS: 32/32 scenarios passed, 5 unsupported, 0 missing findings, 0 unexpected, 0 scan(s) invalid
exit 0
```

`validation.json` summary produced by that run: `scenarios_total 37`,
`scenarios_passed 32`, `scenarios_failed 0`, `scenarios_unsupported 5`,
`expected_findings 57`, `actual_findings 54`, `missing_findings 0`,
`unexpected_findings 0`, `severity_mismatches 0`, `confidence_mismatches 0`,
`duplicate_findings 0`, `dangling_evidence 0`, `findings_without_evidence 0`,
`unaccounted_findings 0`, `scans_validated 5`, `scans_invalid 0`.

Metric caveat, stated because it is easy to misread: `expected_findings 57`
counts matched *expectation instances* (the INV-001/INV-002 calibration
scenarios have 16 and 20 entries that several findings satisfy at once), while
`actual_findings 54` is the raw finding count in the five artifacts
(6+21+25+1+1). The two numbers are not a like-for-like expected/actual pair;
`missing_findings 0` means every expectation matched at least one finding.

Validation classes, kept separate:

| Class | Status |
|---|---|
| Unit tests | Executed, 113 passing |
| Synthetic-fixture tests | Executed (`internal/rules/filesystem`, `internal/platform/...` fixtures) |
| Live local integration | Executed: `./nulq scan` over `lab/fixtures` and over `/tmp/aclfix`; `./nulq system info` |
| Docker end-to-end | **BLOCKED** — not executed (see §11) |
| Lab regression against current M2 source | **Not executed** — validator consumes stale artifacts only |

## 11. Blocked checks

| Check | Status | Reason |
|---|---|---|
| Docker / Alpine lab end-to-end run | **BLOCKED** | The gate directive forbids installing, configuring or starting Docker. The daemon happens to be reachable (`29.9.3`) and `nulq-lab/alpine-target:3.22` exists from a prior run, but no container was started, so no M2-era E2E evidence exists. |
| Container isolation re-verification | **BLOCKED** | Same reason. `lab/results/isolation.json` is an M1.5-era artifact and was not re-derived. Host isolation is **not** claimed on the basis of source inspection. |
| Lab regression against current M2 sources | **BLOCKED** | Requires the Docker lab; the validator only replays the five stale artifacts. |
| `ERANGE` branch of `acl.readOne` | Not exercised | Requires a racing xattr resize; no synthetic syscall seam exists. |

## 12. Permission-model review (source-level, with test backing)

ACL evaluation (`acl.go`), verified against tests:

- Owner match short-circuits to the owner-class entry and the mask.
- Named-user entry wins over owning-group and other classes.
- Owning-group entry and every supplementary group are unioned, then masked
  (group-class union) — `TestEvaluateNamedGroupUnionWithMaskAndSupplementary`.
- Mask applies to named users, owning group and named groups; `other` is
  unmasked, per POSIX.
- Other-class fallback, mode fallback when no ACL is present, and root
  semantics — `TestModeFallbackAndRoot`.
- Malformed/unreadable ACLs evaluate to `unknown`, never to a permissive or a
  `denied` answer (`TestEvaluateUnreadableAndMalformedAreUnknown`,
  `TestReadUnreadablePathStaysUnknown`).
- Absent ACL is `none`/`unsupported`, reported as such, and mode bits are used —
  `TestReadAbsentACLIsNotUnreadable`.

Effective writability:

- `allowed`/`denied`/`unknown` are distinct in `acl.Access` and preserved by
  `effectiveAccess` and `effectiveWritable`.
- `TestEffectiveWritableNormalization` pins: precise attribute wins over a
  conflicting legacy boolean; legacy `true`/`false` map to allowed/denied;
  **no evidence stays `("", false)`** and is never converted to `denied`.
- M1.5 observations (boolean-only) remain readable through the fallback.

Filesystem semantics:

- `ResolveMount` uses longest mount-point boundary with a deterministic tie-break
  (`mount.ID >= best.ID`), covered by tests plus `FuzzParseMountInfo`.
- `HasOption` unions per-mount options with superblock options, so `nosuid` in
  either field is observed; `AllOptions` and `usableMounts` handle exclusions.
- `nosuid` and `noexec` are treated as constraints on execution semantics, not
  as findings by themselves: `NULQ-FS-004` reports them at INFO with MEDIUM
  confidence and states it is not a weakness.
- Sticky-bit protection and parent-directory writability are decided by
  `acl.CanReplaceEntry` when owner IDs are known, and by
  `canReplaceObservation` otherwise.

Finding semantics:

- `NULQ-FS-002` never calls a writable directory a privilege-escalation path by
  itself: MEDIUM is a path-integrity exposure with an explicit "no consumer
  established" impact statement; HIGH requires a root-owned SUID executable on a
  mount without `nosuid`.
- Replaceability (`CanReplaceEntry`) is kept distinct from privileged
  consumption; every finding carries a limitations list saying consumers are not
  enumerated.
- A `worldWritable` directory observation is derived from the mode `other`
  write bit, which the kernel keeps consistent with the ACL `other` entry, so an
  ACL cannot make a 0777 directory look writable while denying other-class
  write. (The kernel clears an ACL that is equivalent to the mode bits and
  rewrites the mode to match a non-equivalent ACL; observed while building the
  D-1 fixture.)
- `unknown` never becomes a false assurance: unknown mount state is reported as
  MEDIUM with an explicit "cannot be confirmed or excluded" reason rather than
  being silently downgraded.

## 13. Known limitations of this verification

1. No Docker E2E and no isolation re-verification (§11). The Alpine lab, the
   `noexec,nosuid,nodev` `/tmp` mount and the container isolation probe are
   unverified for M2.
2. No process-based detection exists yet (D-3), so the process collector's
   parent/exec/mount context is exercised only by unit tests and by
   `nulq system info`, never by a rule.
3. The lab manifest has no scenario for any of the four M2 capabilities, and its
   artifacts are stale, so a green lab validator run says nothing about M2.
4. The ACL fix was validated on this host's filesystem (ext4-family, kernel
   7.3.5) only; `ENOTSUP` filesystems take the `unsupported` path, which is
   covered by unit tests but not by a live run.
5. Coverage is measured with unit tests only; the live CLI paths
   (`internal/app` 22.1%) are exercised manually, not by automated tests.

## 14. Decision

**REJECTED.**

Reason: two material defects were found during this pass — one that silently
disabled the entire POSIX ACL capability on real data (D-1) and one that left a
documented M2 rule unreachable from every command (D-2) — and one material
capability is still absent as a detection (D-3: nothing consumes
`process.info` or the `AttrParent*`/`AttrExe*` attributes, so writable-parent
analysis never runs during `scan`). In addition, the M2 lab deliverable is
unsatisfied: zero scenarios and zero fixtures exist for process observation,
mount flags, ACLs or writable-parent analysis, and the lab artifacts are
M1.5-era, so no end-to-end evidence for any M2 capability exists.

D-1 and D-2 are fixed and verified within this pass. D-3 and the lab gap are
not, so the milestone cannot be accepted.

What would move this to CONDITIONALLY ACCEPTED: D-3 fixed with its own tests,
the lab gap either closed or explicitly descoped, and the Docker gate recorded
as the only remaining blocker.

> Superseded by §15. D-3 is now implemented, tested and exercised through the
> real scan pipeline, and the M2 lab position is explicitly descoped (§15.8).
> The verdict recorded in §15.11 is CONDITIONALLY ACCEPTED; the REJECTED
> verdict above remains part of the audit history.

## 15. D-3 closure pass (2026-11-21)

Scope of this pass: implement, register and verify the process-aware
writable-parent rule, and re-run every gate on the resulting tree. No M3 work,
no commits, no pushes, no Docker, no sudo/root, no host configuration change.

### 15.1 What was added

| Change | Location |
|---|---|
| New rule `NULQ-PROC-001` (module `process`, category `permissions`, `Required: [process]`) | `internal/rules/process/writable_parent.go` (new) |
| 22-case table test, grouping/inconsistency/required-kind/cancellation tests | `internal/rules/process/writable_parent_test.go` (new) |
| Synthetic `/proc` end-to-end harness (4 tests, scenarios SCN-PROC-001…004) | `tests/integration/process_scan_test.go` (new) |
| Registration (7 → 8 rules) | `internal/rules/rules.go` |
| `parent_effective_exec` published; parent mount context no longer overwrites `exe_mount_point`/`exe_nosuid`/`exe_noexec` | `internal/platform/linux/process/collector.go`, `internal/core/models/attributes.go` |
| `ScanConfig.ProcRoot` injection seam (test-only; CLI leaves it empty) | `internal/app/app.go` |
| Corrected global limitation text (ACLs *are* evaluated; process scope stated) | `internal/app/app.go` |
| Registry assertion: 8 rules and `NULQ-PROC-001` declares `Required=[process]` | `internal/cli/cli_test.go` |
| `scan --help` module list now includes `process` | `internal/cli/scan.go` |

New attributes: `AttrParentEffectiveExec`, `AttrParentMountPoint`,
`AttrParentNosuid`, `AttrParentNoexec`. The previous collector wrote the
*parent's* mount flags into the *executable's* attribute keys, so a process
whose executable lived on a different mount than its parent directory was
described with the wrong mount context; the new keys separate the two and
`TestProcessPublishesParentExecAndSeparateMountContext` pins it (asserts
`parent_nosuid=true` and `exe_noexec=true` on two distinct mounts in one
observation).

### 15.2 Detection contract

The rule evaluates, per executable path, the relationship between the running
process identity, the executable's ownership/mode/mount context, and the
immediate containing directory's effective permissions.

Four categories are kept distinct; they are never collapsed into one
"privilege escalation" verdict.

| Category | Trigger | Output | Minimum evidence |
|---|---|---|---|
| 1. Inventory | Any complete/partial `process.info` observation with `exe_path` | No finding; the observation itself is the record | `pid`, `process_euid`, `exe_path` |
| 2. Exposure | Parent effective write+exec for the assessed identity, and a boundary other than "my own unprivileged code" | INFO (LOW/MEDIUM confidence) | `parent_path`, `parent_mode`, `parent_effective_write`, `parent_effective_exec`, `parent_sticky`, `parent_acl_status`, `exe_uid`, `exe_mode` |
| 3. Potential privileged impact | Exposure **plus** a privileged executable (root-owned SUID, group-root SGID, or world-writable SUID) but no observed privileged execution, or mount state that prevents confirming SUID/noexec semantics | MEDIUM (or LOW when `nosuid`/`noexec` constrains it) | Previous set plus `exe_setuid`/`exe_setgid`, `parent_nosuid`, `parent_noexec` |
| 4. Confirmed privilege-boundary weakness | Root-owned SUID executable, replaceable in a non-sticky-protective directory, **and** an observed process executing it with `process_euid == 0`, **and** mount observed `nosuid=false` **and** `noexec=false` | HIGH / HIGH | Previous set plus `process_euid=0` and the `pid` of that process |

Attributes consumed (exhaustive):

```
process:    pid, comm, process_uid, process_euid, start_time
identity:   execution-context euid (identity.execution_context)
executable: exe_path, exe_deleted, exe_readable, exe_regular, exe_uid,
            exe_gid, exe_mode, exe_setuid, exe_setgid, exe_mount_point,
            exe_nosuid, exe_noexec
parent:     parent_path, parent_uid, parent_mode, parent_sticky,
            parent_effective_write, parent_effective_exec,
            parent_acl_status, parent_mount_point, parent_nosuid,
            parent_noexec
```

Outcome ladder (all eight non-silent outcomes are asserted by the table test):

| # | Condition | Severity / Confidence |
|---|---|---|
| 1 | Observations of one path disagree on mount/ACL/ownership state | INFO / LOW — "inconsistent observations", no replaceability claim |
| 2 | Root-owned SUID exe, replaceability UNKNOWN (unknown perms/ACL) | INFO / LOW — "could not be evaluated" |
| 3 | Root-owned SUID exe replaceable, mount `noexec=true` | LOW / HIGH |
| 4 | Root-owned SUID exe replaceable, mount `nosuid=true` | LOW / HIGH |
| 5 | Root-owned SUID exe replaceable, observed euid 0, mount `nosuid=false`,`noexec=false` | **HIGH / HIGH** |
| 6 | Root-owned SUID exe replaceable, observed euid 0, mount state unobserved | MEDIUM / MEDIUM |
| 7 | Root-owned SUID exe replaceable, no privileged execution observed | MEDIUM / MEDIUM |
| 8 | SGID exe owned by group root, replaceable | MEDIUM / MEDIUM |
| 9 | World-writable root-owned SUID exe | HIGH if observed root execution on an unconstrained mount, LOW if `nosuid`/`noexec`, else MEDIUM |
| 10 | Replaceable exe owned by another account (or consumed under another process identity), no privilege evidence | INFO / MEDIUM |
| — | Self-owned, unprivileged exe without SUID/SGID | **silent** (the user can already modify their own code; not a boundary crossing) |

Deliberate conservatism:

- A writable parent directory alone never yields a privilege finding: outcomes 2
  and 10 are INFO, and the silent case covers the assessed user's own code.
- `parent_effective_write`/`parent_effective_exec` come from the ACL-aware
  evaluator (`allowed`/`denied`/`unknown`), not from mode bits alone; the test
  table includes ACL-granted, ACL-denied, mask-limited, named-user and
  supplementary-group cases.
- Sticky protection is only honoured when the directory owner differs from the
  assessed user; `parent_uid` is cited as evidence.
- `exe_deleted=true` (directory entry already gone), `exe_regular=false`,
  non-complete observations without an `exe_path` (kernel threads), and
  unreadable executables are all skipped rather than guessed at.
- One finding per executable path; sharing processes are grouped with their PIDs
  in the explanation, so a shared binary cannot produce duplicate IDs.

### 15.3 Pipeline proof

The rule declares `Required: []models.Kind{models.KindProcess}`, so
`needsProcess()` (`internal/app/app.go:262`) returns true for `--modules process`
and for `--rules NULQ-PROC-001` even when no module is named.

Live scan on this host (real `/proc`, unprivileged):

```
$ ./nulq rules list | tail -1
8 rules. Use `nulq rules list --format json` for full metadata.

$ ./nulq scan --modules process --observations --format json > /tmp/procscan.json
  exit 0
  observations: identity.execution_context 1, identity.group_membership 6,
                process.info 338, system.info 1, system.security_control 6,
                system.sysctl 12
  process statuses: complete 301, partial 36 (unreadable foreign exe), unavailable 1
  observations carrying parent context: 102
  kernel threads without exe: 199
  findings: 0
  coverage.status=complete, coverage.execution_complete=true, scan.partial=true

$ ./nulq scan --rules NULQ-PROC-001 --observations --format json > /tmp/ruleonly.json
  scan.modules = ["process"]           (derived from the rule's Required kinds)
  stats.rules = {total:1, executed:1, skipped:0, failed:0}
  process.info observations: 347
  findings: 0
```

Zero findings on the host is the correct negative control, not a no-op: a sample
observation shows the full context being evaluated and refused —

```
pid 100607 euid 1000
  exe_path=/usr/lib/firefox/firefox exe_uid=0 exe_mode=0755 exe_setuid=false
  exe_nosuid=false
  parent_path=/usr/lib/firefox parent_mode=0755 parent_acl_status=none
  parent_effective_write=denied parent_effective_exec=allowed
  parent_nosuid=false parent_noexec=false
```

Positive path through the *real* `app.Scan` pipeline (synthetic `/proc`, two
processes sharing a SUID executable in a `0777` directory, assessed uid ≠ 0):

```
findings: 1 × NULQ-PROC-001  INFO / MEDIUM
  "Executable consumed by a running process is replaceable by the assessed user"
resource_kind=file, evidence references=17, all resolve against report.evidence
report: ACCEPTED by Draft202012Validator (see §15.7)
scan: 28 observations, 2 process.info, modules=["process"]
```

Full path demonstrated: collector → `process.info` → registry → evaluation →
evidence → finding → JSON.

### 15.4 Tests

`internal/rules/process/writable_parent_test.go` — 22 table cases
(`TestWritableParentRuleCases`), each asserting exact ID, severity, confidence,
title, evidence attribute citations and limitations. Case names and expected
finding counts, verbatim from the test table:

| Case | Findings |
|---|---|
| protected executable and protected parent | 0 |
| writable parent with non-privileged executable | 1 (INFO) |
| world-writable privileged executable observed running as root | 1 (HIGH) |
| world-writable privileged executable with no privileged execution | 1 (MEDIUM) |
| unknown parent permissions for privileged executable | 1 (INFO) |
| unknown parent permissions for unprivileged executable | 0 |
| ACL grants write on a directory whose mode does not | 1 |
| ACL denies write on a world-writable directory | 0 |
| named-user ACL entry with a restrictive mask | 0 |
| supplementary group ACL grant | 1 |
| `nosuid` mount constrains the relationship | 1 (LOW) |
| `noexec` mount constrains the relationship | 1 (LOW) |
| privileged process with unknown mount restriction state | 1 (MEDIUM) |
| replaceable privileged executable with no privileged execution | 1 (MEDIUM) |
| sticky directory owned by another account protects the entry | 0 |
| sticky directory owned by the assessed account does not protect entries | 1 |
| set-group-ID group-root executable is bounded | 1 (MEDIUM) |
| unreadable executable path produces nothing | 0 |
| parent metadata missing | 0 |
| self-owned unprivileged process is not a boundary crossing | 0 |
| deleted executable path | 0 |
| kernel thread | 0 |

Four structural tests cover the remaining required behaviours:

- `TestWritableParentRuleGroupsProcessesByExecutable` — two processes sharing one
executable produce one finding with both PIDs in the explanation.
- `TestWritableParentRuleReportsInconsistentObservations` — divergent path
observations produce an INFO "inconsistent observations" finding and no
replaceability claim.
- `TestWritableParentRuleRequiresProcessObservations` — metadata contract:
`Required` contains `models.KindProcess` and only that kind.
- `TestWritableParentRuleHonoursCancellation` — a cancelled context aborts
  evaluation instead of returning partial findings.

PID reuse / identity change is covered where it is actually decided, in the
collector: `TestPIDReuseDiscardsAttributes` (start-time mismatch discards the
record) and `TestUnreadableProcRootIsExplicit`. Parent-process disappearance
surfaces as the "parent metadata missing" table case.

`internal/platform/linux/process/collector_test.go` —
`TestProcessPublishesParentExecAndSeparateMountContext`.

`tests/integration/process_scan_test.go` — drives `app.Scan` against synthetic
`/proc` trees (no Docker, no root, no host change):

| Scenario | Assertion |
|---|---|
| SCN-PROC-001 | Writable parent + SUID exe shared by 2 PIDs → exactly 1 `NULQ-PROC-001` INFO/MEDIUM finding, evidence resolves, report validates against the schema, ID deterministic across runs |
| SCN-PROC-002 | Self-owned unprivileged exe in a writable directory → **0 findings** (false-positive control) |
| SCN-PROC-003 | Unreadable `/proc/<pid>/exe` → observation recorded, **0 findings**, no fabricated identity |
| SCN-PROC-004 | `--modules filesystem` only → process collector gated off, no `process.info` observations, no process findings |

`internal/cli/cli_test.go` — `TestRulesListCommand` now pins 8 rules and asserts
`NULQ-PROC-001` is registered with `Required=[process]`.

M1.5 regression: `./nulq scan --root lab/fixtures` still reports exactly
`NULQ-ID-001`×2, `NULQ-FS-003`×4, `NULQ-SYS-001`×2, `NULQ-SYS-002`×1 (9
findings); the process collector may now run alongside but contributes no
finding on host processes, so M1.5 expectations are unchanged.

### 15.5 Gates (executed in this pass, on the final tree)

| Check | Result |
|---|---|
| `gofmt -l .` | no output |
| `go vet ./...` | exit 0 |
| `go test ./...` | exit 0, 18 packages ok, **123 top-level tests pass, 0 fail** |
| `go test -race ./...` | exit 0, no races |
| `go test -coverprofile=/tmp/nulq-m2-final-coverage.out ./...` | exit 0 |
| `go tool cover -func=…` | total **66.1%** |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` | exit 0, 5,666,734 B, static ELF x86-64 |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0` | exit 0, 5,347,277 B, static ELF ARM aarch64 |
| `FuzzParseACL` 20 s | PASS, 4,405,245 execs |
| `FuzzParseMountInfo` 20 s | PASS, 1,944,735 execs, no corpus written |
| Lab validator on a copy of `lab/results` | PASS 32/32, 5 unsupported, 0 missing/unexpected/invalid |
| JSON Schema (draft 2020-12) | metaschema valid; live process report and synthetic finding report ACCEPTED |
| `./nulq scan --modules process` | exit 0, 338 `process.info`, 0 findings (correct) |
| `./nulq scan --rules NULQ-PROC-001` | exit 0, 1 rule executed, process module auto-selected |

### 15.6 Coverage delta

Total statement coverage 64.8% → **66.1%**.

| Package | Before | After |
|---|---|---|
| `internal/rules/process` (new) | — | 91.1% (`Evaluate` 94.5%) |
| `internal/platform/linux/process` | 90.3% | 90.4% |
| `internal/rules/filesystem` | 85.7% | 85.7% |
| `internal/platform/linux/acl` | 82.2% | 82.2% |
| `internal/app` | 22.1% | 22.1% (measurement artifact: it is exercised by `tests/integration`, which is a separate package and cannot attribute coverage back) |

### 15.7 JSON Schema

The schema file is unchanged since §9, so the seven mutation rejections recorded
there still describe the same validator inputs; they were **not re-executed** in
this pass. Re-executed here: metaschema `check_schema` → VALID, and two reports
validated with `Draft202012Validator`:

```
/tmp/proc-finding.json (1 NULQ-PROC-001 finding, 17 evidence refs) -> ACCEPTED
/tmp/procscan.json     (live scan, 338 process.info observations) -> ACCEPTED
```

### 15.8 Lab position (explicit descope, not fabrication)

The lab manifest and validator contracts are preserved: `lab/manifest.json` and
`lab/results/` are untouched, and `lab/verify` still reports 32/32 on the
existing artifacts. Those artifacts remain M1.5-era; a green validator run still
says nothing about M2, and this pass does not claim otherwise.

No lab scenario or artifact was added for process detection, deliberately: the
lab harness replays stored reports and has no way to construct a `/proc` tree or
a root-owned SUID executable, so any artifact added there would have to be
hand-written rather than produced by the tool — exactly the fabrication the
gate forbids. The M2 process capability is instead covered by the deterministic
non-Docker harness in §15.4 (SCN-PROC-001…004), which runs the real `app.Scan`
pipeline and validates real findings. These are fixture/synthetic results and
are **not** presented as live process coverage.

### 15.9 Blocked or unexecuted checks

1. **Docker / Alpine lab E2E and container isolation — BLOCKED** by directive
   (daemon reachable, deliberately unused). Not claimed.
2. **Live validation of the HIGH branch** — not possible unprivileged: creating
   a root-owned SUID executable inside a writable directory requires root, which
   the directive forbids. HIGH/MEDIUM privileged outcomes are therefore proven
   by rule-level tests over synthetic attributes through the real `Evaluate`,
   and end-to-end at INFO through the real `app.Scan`. Not claimed as observed
   on a live system.
3. **Cross-filesystem ACL behaviour** (`ENOTSUP` paths) — unit-tested, not
   live-tested.
4. **Schema mutation rejections** — not re-executed (§15.7).

### 15.10 Residual defects and debt (non-material)

- `acl.CanCreate`, `filesystem.AllOptions`, `process.Name` remain exported and
  uncalled (0% coverage).
- `world_writable.go` still has three consecutive sticky-bit guards (correct
  behaviour, harder to audit).
- `internal/app` reports 22.1% coverage because its tests live in another
  package; the real-pipeline harness does exercise `app.Scan`.
- Lab artifacts are stale by design until a Docker run is permitted.

No material correctness or architecture defect is known to remain in M2 scope.

### 15.11 Decision (supersedes §14)

**CONDITIONALLY ACCEPTED.**

All nine acceptance criteria are satisfied as far as this environment allows:
four capabilities implemented (process observation now *consumed*, mount flags,
ACLs, writable-parent analysis), all 8 rules registered, process observations
consumed in normal scans (proven live), evidence-backed writable-parent
findings, UNKNOWN kept conservative, synthetic integration through the real
pipeline, M1.5 clean, all runnable gates green, and no known material defect.

The conditions are environmental, not code gaps:

1. Docker/Alpine lab E2E and container isolation (prohibited by directive).
2. A live privileged-fixture confirmation of the HIGH branch, which needs root.
3. Lab artifact refresh, which depends on (1).

No M3 work was started. No commits or pushes were made.
