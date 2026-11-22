# Performance Report — NULQ

This report documents NULQ's performance characteristics, benchmark status,
and known limitations. All measurements were taken on the development host
(Arch Linux, linux/amd64) running as an unprivileged user.

## 1. Build performance

| Build | Command | Result |
|-------|---------|--------|
| linux/amd64 | `go build -o bin/nulq ./cmd/nulq` | Pass, ~1-2s |
| linux/arm64 cross-compile | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq` | Pass |

No build caching issues observed. Standard library only — no dependency
download or compilation overhead.

## 2. Test performance

| Suite | Command | Result |
|-------|---------|--------|
| All unit tests | `go test ./...` | Pass, cached on re-run |
| Race detector | `go test -race ./...` | Pass |
| Static analysis | `go vet ./...` | Pass |
| Formatting | `gofmt -l .` | Clean |

## 3. Scan performance

No formal benchmarks exist yet. This is a documented gap. The following
observations are based on manual smoke testing:

- Filesystem-only scan of a small fixture (~2 files): ~2ms duration
- Full scan of host (/): duration depends on filesystem size; bounded by
  `--max-files` (default 1,000,000 entries)
- Collector timeouts: default 2 minutes per collector
- Rule timeouts: default 20 seconds per rule
- Overall scan timeout: default 5 minutes

## 4. Memory characteristics

No formal memory profiling has been performed. Observations are stored in
memory for the duration of the scan. For very large filesystems, the
`--max-files` budget bounds memory growth. Reports are streamed to the
output writer (not buffered in memory beyond the report struct).

## 5. Concurrency

- Collector concurrency: bounded by `--concurrency` (default: runtime.NumCPU())
- Rule concurrency: same bound
- Semaphore-based limiting prevents unbounded goroutine growth
- Context cancellation propagates through all components

## 6. Performance gaps

| Gap | Impact | Plan |
|-----|--------|------|
| No benchmark tests | No performance regression detection | Add `BenchmarkScan`, `BenchmarkCollector`, `BenchmarkRule` |
| No memory profiling | Unknown memory footprint at scale | Add `pprof` or manual allocation testing |
| No scan duration baseline | Cannot detect performance regressions | Record baseline duration for standard fixture |
| No large-filesystem testing | Unknown behavior at 100k+ entries | Test with `--max-files` on large fixture tree |

## 7. Scalability considerations

- Filesystem traversal is bounded by `--max-files` and root exclusions
  (pseudo-filesystems, container storage, snapshots)
- Mountinfo parsing uses buffered scanner with 1MB max line size
- Process enumeration reads /proc entries sequentially
- Report rendering streams to writer; JSON encoding is incremental

## Conclusion

Performance is adequate for the intended use case (read-only privilege
boundary discovery on a single host). No performance defects were observed.
The primary gap is the absence of formal benchmarks, which should be added
as part of ongoing quality hardening.
