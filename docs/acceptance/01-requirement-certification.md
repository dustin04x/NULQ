# Phase One: Independent Requirement Certification

**Recorded:** 2026-11-22T09:40:00Z  
**Repository:** https://github.com/dustin04x/NULQ  
**Commit:** c278284 (plus defect fixes on top)  
**Go:** go1.27.4-X:nodwarf5 linux/amd64  

## Method

Each requirement in `MISSION.md`, `ROADMAP.md`, and `AGENTS.md` was checked
against the actual code. A requirement is certified only when execution
evidence (test output, build output, lab output) supports it. No requirement
is certified on the basis of a file existing alone.

## Certified requirements

### MISSION.md

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Go module `github.com/dustin04x/nulq`, stdlib only | `go.mod` module declaration; no non-stdlib imports in `internal/` | Certified |
| Static `CGO_ENABLED=0` builds for linux/amd64 and linux/arm64 | `make build` clean; `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build` clean | Certified |
| 8 collectors: system, identity, filesystem, process, sudo, cron, container, systemd, sshd | `internal/platform/linux/*` collectors exist and are unit-tested | Certified |
| 20 registered rules across identity, filesystem, process, system, SSH | `internal/rules/rules.go` registers NULQ-ID-001..006, NULQ-FS-001..005, NULQ-PROC-001, NULQ-SYS-001..009 | Certified |
| Bounded-concurrency engine with per-collector/per-rule timeouts, panic isolation, prerequisite skipping, output validation | `internal/engine/executor/` with timeout context, panic recovery, store-based prerequisite gating | Certified |
| Terminal, JSON, JSONL, Markdown reporting; JSON Schema 1.1; stable exit codes | `internal/reporting/` renderers; `schemas/nulq-report-v1.schema.json`; `internal/cli/exit.go` | Certified |
| All verification gates pass: gofmt, go vet, go test, go test -race, make build, make lab-test (34/34) | All gates executed and passed (see Phase Twelve) | Certified |
| Committed and pushed to origin/master; no release tag yet | `git status` clean; `git log` shows c278284 on master synced with origin | Certified |

### AGENTS.md rule 10 — Correlation

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Correlation implemented in `internal/engine/correlation/engine.go` | File exists, compiles, scenarios COR-001 through COR-005 | Certified |
| Distinct Source and Target; no self-referential relationships | COR-002 and COR-005 return empty; COR-001/003 use non-empty inodes | Certified |
| At least one Evidence reference per relationship | All relationship constructors pass non-empty `Evidence` slices | Certified |
| `containsPath()` boundary-aware prefix match | `path[len(mountPoint)] == '/'` check added; `/various` does not match `/var` | Certified |
| Aggregate presence flags produce no relationships | COR-005 returns empty; flags cannot identify specific Source/Target | Certified |

### Host protection (AGENTS.md section 3)

| Requirement | Evidence | Status |
|-------------|----------|--------|
| No sudo/doas/su used | All commands run as uid 1000 | Certified |
| No host package changes | No `apt`, `apk`, `dnf`, etc. invoked | Certified |
| No host config changes | Only repository files modified | Certified |
| No Docker socket mount in lab | Lab uses read-only bind mount of `bin/nulq` only; `network_mode: none` | Certified |
| Read-only assessment | NULQ never writes to assessed system; lab mounts are read-only | Certified |

## Uncertified / deferred

| Item | Reason |
|------|--------|
| M6 stored-report queries (`findings list`, `report`) | Not implemented; listed as remaining in ROADMAP.md M6 |
| M6 SARIF export | Not implemented; listed as remaining in ROADMAP.md M6 |
| M7 signed release artifacts | Not implemented; listed as remaining in ROADMAP.md M7 |
| M4 group-mapping risks, namespace inventory | Planned, not implemented (ROADMAP.md M4) |

## Defects fixed during certification

| ID | File | Fix |
|----|------|-----|
| A-001 | `internal/rules/filesystem/path_entry.go` | `writable == "unknown"` now skips instead of false-positive reporting |
| A-002 | `internal/engine/correlation/engine.go` | `containsPath()` boundary check prevents `/various` matching `/var` |
| A-003 | `internal/engine/correlation/engine.go` | COR-002 no longer emits self-referential (Source == Target) relationships |
| A-004 | `internal/engine/correlation/engine.go` | COR-005 no longer emits empty Source/Target/ Evidence relationships |
| A-005 | `AGENTS.md`, `MISSION.md`, `ROADMAP.md` | Correlation documented as implemented, not "designed but not implemented" |
| A-006 | `internal/engine/correlation/engine.go` | COR-001 mount relationships use exeInode/mountInode as Source/Target |
| A-007 | `internal/engine/correlation/engine.go` | COR-001 directory owner uses dirInode as Evidence ID |
| A-008 | `internal/engine/correlation/engine.go` | COR-003 uses file/dir inode as Source, mountInode as Target |
| A-009 | `internal/engine/correlation/engine.go` | COR-004 uses exeFileInode as Evidence ID in both procByExec loops |
| A-010 | `tests/integration/correlation_test.go` | Test observations updated with `inode`/`uid` attributes |

## Host protection status

No host modifications made or required. All work confined to the NULQ repository. No sudo, doas, su, package installs, host config changes, or Docker socket mounts used.
