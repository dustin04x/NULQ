# NULQ v1.0.0 — release notes DRAFT

Status: draft for review. This document has not been published, and no release
exists for v1.0.0. Dates and achievements below are drawn only from verified
project history (`CHANGELOG.md`, `ROADMAP.md`, `MISSION.md`, git history);
nothing about v1.0.0 itself is claimed beyond what was executed in this
preparation session. Placeholders marked `[TBD]` must be resolved by the
maintainer before publication.

## Version

v1.0.0 (first stable release, draft). Previous development line: `0.1.0-dev`,
which is unreleased and has no tag or published artifact; see `CHANGELOG.md`
for its entry.

## Headline (draft)

NULQ v1.0.0 is a read-only Linux privilege-boundary discovery and
evidence-driven security assessment framework: a single static Go binary that
collects normalized observations, evaluates detection rules, and emits findings
traceable to evidence item IDs. Standard library only; no runtime dependencies.

>[!NOTE] Placeholder content — the maintainer must confirm the v1.0.0 feature
>set, any deprecations, and upgrade guidance before publication.

## What is verified for this build

- Built with `make release VERSION=1.0.0`: linux/amd64 and linux/arm64,
  static (`CGO_ENABLED=0`, `-trimpath`), linker-injected version metadata.
- `dist/nulq-1.0.0-linux-amd64 version --format json` reports
  `version: "1.0.0"`, commit `25c0c86`, build date `2026-11-23T15:23:28Z`,
  platform `linux/amd64`.
- `make verify`: `SHA256SUMS` check passes for both artifacts.
- Verification gates: `gofmt -l .` empty, `go vet ./...` clean,
  `go test ./...` pass, `go test -race ./...` pass.
- `make build` host binary works; `nulq version`, `nulq rules list`,
  `nulq scan` CLI contract intact (exit codes 0/1/2/3).
- Laboratory: `make lab-test` acceptance criteria as documented in
  `MISSION.md` (34/34 supported scenarios, 5 unsupported, schema-valid
  reports — evidence dated 2026-11-22; re-run required for a formal release).

## Based on verified history (not v1.0.0 claims)

The following is carried from `CHANGELOG.md` [0.1.0-dev] and `ROADMAP.md` as the
project's demonstrated baseline; it is not a list of v1.0.0 additions:

- Observation-first pipeline: 9 collectors
  (`linux.system`, `linux.identity`, `linux.filesystem`, `linux.process`,
  `linux.sudo`, `linux.cron`, `linux.container`, `linux.systemd`,
  `linux.sshd`) and 20 registered rules
  (`NULQ-ID-001`–`ID-004`, `NULQ-ID-006`, `NULQ-FS-001`–`FS-005`,
  `NULQ-PROC-001`, `NULQ-SYS-001`–`SYS-009`).
- Evidence-backed findings; every finding cites observation IDs; aggregation
  enforces referential integrity and deterministic ordering.
- Report formats: terminal, JSON, JSONL, Markdown; SARIF 2.1.0 export; JSON
  Schema 1.1; output files mode 0600; terminal-injection sanitization.
- CLI: `scan`, `system info`, `rules list`, `version`, `report list`, `report
  show`, `report export`, `report delete`, `baseline create`, `baseline list`,
  `baseline show`, `baseline delete` and `baseline compare`; stable exit codes;
  `--fail-on` severity gate.
- Typed error model; honest unavailability reporting; bounded concurrency
  with per-rule/per-collector timeouts and panic isolation.
- Docker laboratory: pinned Alpine 3.22 target, non-root unprivileged user,
  all capabilities dropped, `no-new-privileges`, read-only root filesystem,
  `network_mode: none`, no host namespaces, no Docker socket.

## Deferred work (not in this build)

Per `ROADMAP.md` and `MISSION.md`:

- M4 remaining items: group-mapping risk analysis, per-process namespace
  inventory/divergence, and the distribution compatibility matrix.
- M7 remaining items: signed release artifacts, performance-budget regression
  tests, privileged opt-in integration tests, broader configuration-parser
  fuzzing, and a final independent release review.

M6 (report persistence, report commands, baselines, differential analysis and
SARIF export) is implemented; see `ROADMAP.md`.

## Checksums

```
[TBD: insert dist/SHA256SUMS contents at release time]
```

Artifacts: `nulq-1.0.0-linux-amd64`, `nulq-1.0.0-linux-arm64`,
`SHA256SUMS` (produced by `make release VERSION=1.0.0`, verified with
`make verify`).

## Security

See `SECURITY.md`. NULQ is read-only, makes no network connections, runs
unprivileged, and does not execute discovered binaries. Reports contain host
configuration details and must be treated as sensitive.

## Installation

```bash
# linux/amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath ./cmd/nulq
# linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath ./cmd/nulq
```

Prebuilt artifacts and checksums are attached to the GitHub release when
published (not yet).
