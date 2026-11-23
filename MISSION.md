# NULQ mission

This file describes the **current** engineering mission. The permanent rules
are in `AGENTS.md`; milestone history is in `ROADMAP.md`.

## Current state

NULQ is a working v0.1.0 foundation:

- Go module `github.com/dustin04x/nulq`, standard library only, static
  `CGO_ENABLED=0` builds for linux/amd64 and linux/arm64.
- Observation pipeline with `linux.system`, `linux.identity`,
  `linux.filesystem`, `linux.process`, `linux.sudo`, `linux.cron`,
  `linux.container`, `linux.systemd` and `linux.sshd` collectors.
- Twenty registered rules across identity, filesystem, process, system
  and SSH domains: `NULQ-ID-001` through `NULQ-ID-004`, `NULQ-ID-006`,
  `NULQ-FS-001` through `NULQ-FS-005`, `NULQ-PROC-001`, `NULQ-SYS-001`
  through `NULQ-SYS-009`. Rule ID `NULQ-ID-005` is not registered in v0.1.0.
- Bounded-concurrency engine with per-collector and per-rule timeouts, panic
  isolation, prerequisite skipping and output validation.
- Terminal, JSON, JSONL and Markdown reporting; JSON Schema 1.1; stable exit
  codes.
- All verification gates pass: `gofmt`, `go vet`, `go test`, `go test -race`,
  `make build`, `make lab-build`, `make lab-test` (34/34 scenarios).
- M1.5 independent audit documented in `docs/audits/m1.5-baseline.md` and
  `docs/audits/m1.5-final-engineering-report.md`; severity semantics in
  `docs/architecture/severity-confidence-model.md`.
- Committed and pushed to `origin/master`; release tag `v0.1.0` exists.

Known unimplemented areas, deliberately out of scope here: stored-report
queries (M6), release signing (M7).

## Objective

Make NULQ verifiable without a second machine, a VM or manual setup, while
proving that development cannot damage the owner's primary Ryoku workstation.

1. Persistent project governance (`AGENTS.md`, `MISSION.md`, roadmap, changelog,
   security policy, ADRs).
2. An explicit host-protection policy, enforced in the tooling.
3. A fully automated Docker laboratory that builds the real NULQ binary,
   executes it unprivileged inside a minimal Alpine target, validates the JSON
   against the published schema, evaluates scenario expectations, writes
   reproducible reports and cleans up only its own resources.
4. Honest coverage reporting that separates execution success from observation
   completeness.

## Laboratory architecture

```text
make lab-test
  │
  ├── go build ─────────────► bin/nulq                      (real binary)
  ├── docker compose build ─► nulq-lab/alpine-target:3.22   (pinned digest)
  ├── lab/scripts/lab-probe ─► results/isolation.json       (isolation proof)
  ├── docker compose run ───► scan.json                     (full Alpine)
  │                            scan-fixtures.json           (fixture root)
  │                            scan-path.json               (hostile PATH)
  │                            scan-identity.json           (wheel membership)
  │                            scan-discovery.json          (auto-discovered mounts)
  ├── lab/verify ───────────► validation.json               (schema + scenarios)
  └── lab/verify ───────────► summary.md                    (human report)
```

Container security baseline (identical for every service):

- non-root uid/gid 10001;
- `cap_drop: ALL`, `no-new-privileges`;
- read-only root filesystem, size-limited `noexec,nosuid,nodev` `/tmp`;
- `network_mode: none`; no host namespaces; no Docker socket;
- read-only bind mount of `bin/nulq` only;
- NULQ-labelled resources for targeted cleanup.

Fixtures are synthetic configuration created inside the image. Baseline scans
mount an empty tmpfs over `/lab/fixtures` so live Alpine observations are never
mixed with fixture observations. Unsupported categories are reported as
**unsupported** scenarios, never as passes.

## Implementation phases

| Phase | Content | State |
|---|---|---|
| A | Repository and Docker reconnaissance | complete |
| B | Governance documents | complete |
| C | Host-protection policy | complete |
| D | Lab architecture (Compose, image, fixtures, scenarios) | complete |
| E | Secured Alpine image | complete |
| F | Deterministic fixtures and scenario manifest | complete |
| G | Real-binary execution inside the lab | complete |
| H | Validation, coverage checks, reports | complete |
| I | Makefile interface and cleanup | complete |
| J | End-to-end verification and review | complete |

## Acceptance criteria

`make lab-test`, with Docker available and no further interaction:

1. builds `bin/nulq` and the pinned Alpine image;
2. proves non-root execution, read-only root, zero effective capabilities,
   `no-new-privileges`, network isolation and absent Docker socket;
3. runs five real scans inside the container (baseline, fixtures, PATH,
   identity, auto-discovered mounts);
4. validates every report against `schemas/nulq-report-v1.schema.json`;
5. passes every supported scenario and reports unsupported categories as
   unsupported;
6. writes `lab/results/scan.json`, `validation.json`, `summary.md` and the
   supporting scan artifacts;
7. exits non-zero when any supported scenario fails;
8. leaves no running NULQ containers after `make lab-cleanup` and touches no
   unrelated Docker resource.

## Verification evidence (2026-11-22)

- `make lab-test`: **34/34 supported scenarios passed**, 5 unsupported, 0
  missing findings, 0 unexpected findings, 0 unaccounted findings,
  0 severity/confidence mismatches, 0 duplicate findings, 0 dangling evidence,
  0 findings without evidence, 5/5 reports schema-valid under both the Go
  validator and Python `jsonschema`. The manifest contains 39 scenarios
  (34 supported, 5 explicitly unsupported).
- `gofmt -l .`: empty. `go vet ./...`: clean. `go test ./...`: all pass.
- `go test -race ./...`: all pass (race detector clean).
- `make build`: clean (linux/amd64). Cross-compile `linux/arm64` (`CGO_ENABLED=0`):
  clean.
- Isolation probe: 9/9 checks passed (uid 10001, read-only root, zero effective
  capabilities, `no-new-privileges`, no routable network, no Docker socket,
  binary executes, `/tmp` writable and non-executable).
- Coverage: baseline `partial` (1 denial: `/root`); discovery `partial`
  (1 denial, 16 deliberately excluded mounts including `/proc` and `/sys`);
  fixture/PATH `partial` (3 denials each); identity `complete`.
  `failed_operations` is empty in every scan; deliberate exclusions are
  reported separately from traversal failures.
- Detection semantics corrected: PATH writability is LOW without an observed
  privileged consumer; SUID location, non-root ownership and inert
  non-executable bits are no longer treated as vulnerabilities;
  world-writable directories escalate only for a directly replaceable root-owned
  SUID executable; user-owned sticky directories handled correctly.
- Host: run as uid 1000, no root-owned repository files, no NULQ containers
  left behind, no global Docker prune, no `sudo`, no host package, service,
  sysctl or network change.

## Test requirements

- `gofmt -l .` empty, `go vet ./...`, `go test ./...`, `go test -race ./...`,
  `go test -cover ./...` executed and reported truthfully.
- Lab validator unit tests for schema constructs, resource matching and verdict
  logic.
- Repeated `make lab-test` runs produce identical scenario verdicts.
- Failure paths: missing Docker, missing binary, container failure, stopped
  container cleanup.

## Deliverables

- `AGENTS.md`, `MISSION.md`, updated `ROADMAP.md`, `CHANGELOG.md`, `SECURITY.md`.
- ADRs 0008 (laboratory platform) and 0009 (coverage classification).
- `lab/` with Compose file, Dockerfile, fixtures, scenario manifest, scripts,
  validator source and results directory.
- Documentation: `lab/README.md`, `docs/architecture/lab-architecture.md`,
  `docs/testing/scenario-design.md`, `docs/testing/docker-security-model.md`,
  README lab section.
- Coverage contract in the report model and JSON Schema 1.1, including
  excluded mounts and classified failed operations.
- Independent audit documents and the severity/confidence model.

## Known limitations

- Alpine is a minimal BusyBox userland; it cannot represent systemd, PAM,
  SELinux or distribution package layout. Those checks are synthetic fixtures
  or unsupported scenarios.
- The container kernel is shared with the Docker host (Docker Desktop LinuxKit
  VM); sysctl values describe that kernel, not a bare-metal server.
- Docker is a prerequisite and is not installed by this project.
- `--root /lab/fixtures` intentionally narrows filesystem discovery; those
  scans are fixture observations, not host assessments.
- NULQ itself remains read-only; the lab verifies this by behaviour (no writes
  succeed) rather than by kernel auditing.

## Next milestones

1. **M4** — Advanced Linux analysis (group-mapping risks, namespace inventory,
   distribution compatibility matrix). Container indicators (NULQ-SYS-008) and
   kernel mitigations (NULQ-SYS-007) are already implemented; remaining M4
   items are planned.
2. **M5** — Relationship and correlation engine (designed, not implemented;
   AGENTS.md rule 10).
3. **M6** — Reporting and integration (stored-report queries, severity baselines,
   diffing, SARIF export evaluation).
4. **M7** — Hardening and release (broader fuzzing, performance budget
   regression tests, independent security review, signed release artifacts,
   v0.1.0 tag).
