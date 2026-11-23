# Reproducible build procedure — NULQ v1.0.0

## Command

Host release build (amd64):

```bash
make release VERSION=1.0.0
```

Equivalent explicit form:

```bash
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags \
  "-s -w \
   -X github.com/dustin04x/nulq/internal/version.Version=1.0.0 \
   -X github.com/dustin04x/nulq/internal/version.Commit=<git rev-parse --short HEAD> \
   -X github.com/dustin04x/nulq/internal/version.BuildDate=<RFC3339 UTC>" \
  -o dist/nulq-1.0.0-linux-amd64 ./cmd/nulq
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" \
  -o dist/nulq-1.0.0-linux-arm64 ./cmd/nulq
cd dist && sha256sum nulq-1.0.0-linux-amd64 nulq-1.0.0-linux-arm64 > SHA256SUMS
```

Verify:

```bash
make verify   # cd dist && sha256sum -c SHA256SUMS
```

## Version/build metadata

Metadata is injected at link time; source defaults are honest development
values (`0.1.0-dev`, `unknown`) so an unflagged build never masquerades as a
release.

| Field | Source | Default |
|-------|--------|---------|
| `version` | `-X ...Version=$(VERSION)` | `0.1.0-dev` |
| `commit` | `-X ...Commit=$(git rev-parse --short HEAD)` | `unknown` |
| `build_date` | `-X ...BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)` | `unknown` |

Observed for this preparation (`make release VERSION=1.0.0`):

```
version: "1.0.0"
commit: "25c0c86"
build_date: "2026-11-23T15:23:28Z"
go_version: "go1.27.4-X:nodwarf5"
platform: "linux/amd64"
```

`nulq version --format text` prints the same fields in human-readable form;
`--format json` emits machine-readable output suitable for pipeline ingestion.

## Reproducibility notes

- `-trimpath` removes build-host path information.
- Go's build cache and module cache are deterministic for a fixed toolchain and
  dependency set (standard library only).
- `BUILD_DATE` uses the wall-clock build time by default, so byte-identical
  reproduction across build times requires `SOURCE_DATE_EPOCH`-aware tooling or
  an explicit fixed `BUILD_DATE`; the Makefile does not currently force this,
  so reproducibility is "same source + same toolchain + same build date" rather
  than fully bit-for-bit across arbitrary times. Treat this as a limitation,
  not a claim.
- Commit SHA ties the artifact to exactly one git state; `unknown` means the
  build was not performed inside a git repository.
- Binaries are stripped (`-s -w`), which reduces size but removes symbol
  information; this is intentional for release artifacts.

## Verification performed in this session

- `make build` (linux/amd64) — OK.
- `make release VERSION=1.0.0` — produced amd64 + arm64 static ELF binaries;
  `make verify` — both checksums OK.
- `dist/nulq-1.0.0-linux-amd64 version --format json` — version 1.0.0,
  commit 25c0c86, build date present, platform linux/amd64.
- `file dist/nulq-1.0.0-linux-arm64` — ELF 64-bit LSB aarch64, statically
  linked.
- `gofmt -l .`, `go vet ./...`, `go test ./...`, `go test -race ./...` — all
  clean/pass.
