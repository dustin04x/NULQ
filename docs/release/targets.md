# Supported build targets — rationale

NULQ targets Linux only. Go's standard library provides the `/proc`, `/sys`,
mount, xattr, LSM and credential interfaces NULQ depends on; non-Linux
operating systems are explicitly out of scope and would require separate
collectors. Go version 1.24.0+ is required (`go.mod` `go 1.24.0`).

## Targets

| GOOS | GOARCH | Binary | Notes |
|------|--------|--------|-------|
| linux | amd64 | `nulq-1.0.0-linux-amd64` | Primary target; development host architecture |
| linux | arm64 | `nulq-1.0.0-linux-arm64` | Secondary target; statically linked aarch64 ELF |

Both are produced by `make release` (`make release VERSION=1.0.0`).

## Build constraints

- `CGO_ENABLED=0`: static binaries with no libc or C toolchain dependency;
  avoids glibc version portability issues across Linux distributions.
- `-trimpath`: removes local filesystem paths from the binary for
  reproducibility and to avoid leaking build-host paths.
- Linker flags inject `Version`, `Commit` and `BuildDate` into
  `internal/version` (`docs/release/reproducible-builds.md`).
- No `sudo`, no host package installation, no host services, no network: the
  release build runs entirely as the unprivileged owner account
  (`AGENTS.md` host-protection policy).

## Why no other targets

- macOS/Windows: NULQ collects Linux-specific kernel state; no collectors
  exist for other platforms. Cross-compiling without runtime validation would
  produce unverifiable artifacts.
- linux/386, linux/mips, etc.: not tested in CI or the laboratory; an
  untested target cannot be supported honestly (AGENTS.md rule 4: no
  fabricated results).
- Darwin/Windows would require CGO or standard-library gaps for the interfaces
  used; adding them is a new-collector project, not a release target.

## Verification

`go test` and `go test -race` run on linux/amd64. `make lab-test` runs the
real binary inside the pinned Alpine container (linux/amd64 host or emulated
target). The arm64 artifact is compiled but cannot be executed on an amd64
host without emulation; its correctness rests on the same static, dependency-free
build path and `go vet`/type-check coverage.
