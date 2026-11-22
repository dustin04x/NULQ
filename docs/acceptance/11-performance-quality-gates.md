# Phase Eleven: Performance and Resource Certification

**Recorded:** 2026-11-22T09:50:00Z  

## Performance measurements

| Operation | Duration | Notes |
|-----------|----------|-------|
| `nulq version` | <100ms | Minimal startup |
| `nulq system info` | <200ms | Host inspection only |
| `nulq rules list` | <100ms | Registry read only |
| `nulq scan --format json` (full host) | ~7.6s | 507K files, 51K directories |
| `nulq scan --root /tmp --format json` | ~1s | Narrow scope |
| `make lab-test` | ~60s | Build + 5 container scans + validation |
| `go test ./...` | ~7s | All packages |
| `go test -race ./...` | ~11s | Race detector enabled |

## Resource usage

- Binary size: ~10MB (static, CGO_ENABLED=0, trimmed)
- Memory: bounded by `DefaultMaxProcesses` for process enumeration
- No memory leaks detected (race-clean)
- No goroutine leaks (bounded concurrency with context timeouts)

## Race detection

`go test -race ./...` — all packages pass, race detector clean.

## Cross-compilation

- linux/amd64: clean
- linux/arm64 (CGO_ENABLED=0): clean

## No performance defects found

Performance is acceptable for a read-only discovery tool. No memory or goroutine
leaks. Race-clean. Cross-compilation works for both amd64 and arm64.

## Limitation

No formal performance budget regression tests exist yet (listed as M7 remaining
work in ROADMAP.md).
