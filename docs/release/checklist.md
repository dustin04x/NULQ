# NULQ release checklist — v1.0.0 (draft, not published)

Status: preparation only. No tag, no push, no GitHub release, no artifact
publication has been performed. Every item below must be executed and evidenced
before a maintainer may approve the release.

## 1. Pre-release

- [ ] Code freeze on `master`; no unrelated changes merged after freeze.
- [ ] `CHANGELOG.md` `[Unreleased]` section converted to a dated `[1.0.0]`
  entry; only verified changes listed (no fabricated achievements or dates).
- [ ] `MISSION.md`/`ROADMAP.md` updated to reflect v1.0.0 as the current release
  and the next milestone as in-progress.
- [ ] `SECURITY.md` supported-versions table updated (0.1.x → 1.0.x).
- [ ] README release badge and installation text reviewed against the version
  being released.
- [ ] All open release-blocking issues resolved or explicitly deferred with a
  recorded reason.
- [ ] Dependencies: standard library only (no new dependencies introduced;
  ADR 0002). No `go.mod`/`go.sum` changes without an ADR.

## 2. Validation

Execute in order; each step must exit 0 or its failure must be recorded as a
limitation, not treated as a pass.

- [ ] `gofmt -l .` — empty output.
- [ ] `go vet ./...` — clean.
- [ ] `go test ./...` — all packages pass.
- [ ] `go test -race ./...` — race detector clean.
- [ ] `make build` — host `bin/nulq` builds statically (`CGO_ENABLED=0`,
  `-trimpath`).
- [ ] `make release VERSION=1.0.0` — produces
  `dist/nulq-1.0.0-linux-amd64` and `dist/nulq-1.0.0-linux-arm64`.
- [ ] `make verify` — `sha256sum -c SHA256SUMS` passes for both artifacts.
- [ ] `./dist/nulq-1.0.0-linux-amd64 version --format json` reports
  `version: "1.0.0"`, a real commit SHA, and a real build date
  (never `unknown` or fabricated values).
- [ ] `./dist/nulq-1.0.0-linux-amd64 rules list --format json` emits the
  registered rule set with metadata (ids, versions, severity).
- [ ] `make lab-test` (Docker available): 34/34 supported scenarios pass,
  unsupported reported as unsupported, all reports schema-valid.
- [ ] Determinism: two consecutive `make release VERSION=1.0.0` builds
  produce byte-identical binaries when `SOURCE_DATE_EPOCH` is fixed
  (see `docs/release/reproducible-builds.md`).

## 3. Artifacts

- [ ] `dist/nulq-1.0.0-linux-amd64` — static ELF, linux/amd64, stripped
  (`-s -w`), executable bit set.
- [ ] `dist/nulq-1.0.0-linux-arm64` — static ELF, linux/arm64 (aarch64),
  stripped, executable bit set.
- [ ] `dist/SHA256SUMS` — `sha256sum` output for both artifacts, verified with
  `make verify`; file readable (0644), binaries executable (0755).
- [ ] No `unknown` values in embedded version metadata of either artifact.
- [ ] Artifacts are **not** uploaded, attached to a release, or announced.
- [ ] Checksums recorded in this checklist only after `make verify` passes.

## 4. Approval

- [ ] Maintainer reviews this checklist with attached command output as
  evidence.
- [ ] Maintainer approves tagging `v1.0.0` on the exact commit used for the
  artifacts.
- [ ] Only after approval: `git tag v1.0.0`, push tag, GitHub release
  (workflow `.github/workflows/release.yml` builds and publishes artifacts
  from the tag automatically).
- [ ] No release is created without an explicit maintainer instruction; this
  preparation stops at artifact production and verification.

## Evidence captured for this preparation

- `gofmt`, `go vet`, `go test`, `go test -race`: all clean (see session
  output).
- `make release VERSION=1.0.0` + `make verify`:
  `a7fdc6a2...  nulq-1.0.0-linux-amd64`,
  `f52c3a95...  nulq-1.0.0-linux-arm64`, both OK.
- `dist/nulq-1.0.0-linux-amd64 version --format json`:
  version 1.0.0, commit 25c0c86, build date 2026-11-23T15:23:28Z,
  platform linux/amd64.
- `nulq-1.0.0-linux-arm64`: ELF 64-bit LSB aarch64, statically linked.
