# NULQ

<p align="center">
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/platform-linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/release-0.1.0-green?style=for-the-badge" alt="Release"/>
  <img src="https://img.shields.io/badge/deps-stdlib_only-orange?style=for-the-badge" alt="Dependencies"/>
</p>

<p align="center">
  <strong>Find the boundary. Understand the exposure.</strong><br/>
  A read-only Linux privilege-boundary discovery and evidence-driven security assessment framework.
</p>

---

## Overview

NULQ answers one question precisely: **how does this system grant authority, and what evidence supports that claim?**

It is a static, dependency-free Go binary that collects normalized observations about how a Linux system grants authority, evaluates detection rules against those observations, and emits findings traceable back to the exact facts that caused them. It never exploits, executes, or modifies anything on the assessed system.

NULQ is authorised-use software for post-access assessments, hardening reviews, CTF and laboratory environments, and automated security pipelines. It is **not** an exploitation tool, a persistence tool, or a remote-control service.

---

## Why NULQ

- **Observation-first.** Collectors normalise system state into a closed vocabulary of observation kinds. Rules consume a shared store and never traverse the filesystem themselves.
- **Evidence-backed.** Every finding cites at least one evidence item that resolves to an observation ID. Evidence identifies the observation, the field, and the observed value — never a conclusion.
- **Conservative conclusions.** Presence is not vulnerability. Unknown or incomplete evidence is never treated as confirmed exploitability. When a rule cannot decide, it reports less, not more.
- **Honest coverage.** A completed execution is not a complete assessment. Coverage separates `execution_complete` from `coverage_complete`, and both are published. Permission-denied paths are reported as unavailable, never silently swallowed.

---

## Capabilities

| Domain | Rules | What they detect |
|--------|-------|------------------|
| Identity | `NULQ-ID-001` … `ID-006` | Privileged group membership, sudoers policy, cron jobs, non-root UID-0 accounts, writable SSH authorized_keys |
| Filesystem | `NULQ-FS-001` … `FS-005` | SUID/SGID executables, world-writable directories, unsafe PATH entries, mount flag constraints, file capabilities |
| Process | `NULQ-PROC-001` | Writable parent directory of an executable consumed by a running process |
| System | `NULQ-SYS-001` … `SYS-009` | Kernel sysctl hardening, MAC posture, process capabilities, seccomp, systemd unit hardening, user namespaces, kernel mitigations, container indicators, sshd configuration |

Run `nulq rules list --format json` for full rule metadata.

---

## Installation

NULQ is a single static binary with no runtime dependencies. Go **1.24.0+** is required to build.

```bash
# Build for the host architecture
make build

# Cross-compile for linux/amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/nulq

# Cross-compile for linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq
```

Release artifacts (with checksums) are produced via `make release`.

---

## Quick start

```bash
# CLI reference
nulq --help

# Full assessment (terminal output)
nulq scan

# JSON report to a file (created with mode 0600)
nulq scan --format json --output report.json

# Scan specific modules only
nulq scan --modules identity,filesystem

# Scan specific rules only
nulq scan --rules NULQ-FS-001,NULQ-PROC-001

# List registered rules
nulq rules list

# Show collected system facts
nulq system info

# Print build metadata
nulq version
```

Diagnostics go to **stderr**. Machine-readable output never contains banners, progress output, colour, or log records.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no failure threshold met |
| `1` | Runtime failure (I/O error, cancellation, invalid internal state) |
| `2` | Usage error (unknown flag, module, rule, format, command) |
| `3` | `--fail-on` set and a finding met or exceeded the threshold |

```bash
# Exit 3 when any finding at MEDIUM or above exists
nulq scan --fail-on medium
```

---

## Output formats

| Format | Use |
|--------|-----|
| `terminal` | Human-readable report with optional colour (default) |
| `json` | Structured JSON report, schema version 1.1 |
| `jsonl` | JSON Lines, one object per line |
| `markdown` | Markdown report for documentation and sharing |

Output files are created with mode `0600`. Reports are sensitive — they can contain host configuration details.

---

## Testing and verification

```bash
gofmt -l .          # must be empty
go vet ./...        # static analysis
go test ./...       # unit and integration tests
go test -race ./... # race detector clean
make build          # host binary
make lab-test       # Docker laboratory: 34/34 scenarios pass, 5 unsupported
```

The laboratory builds the real binary, executes it unprivileged inside a
pinned Alpine container, and validates output against the published JSON
schema and the scenario manifest.

---

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built with the Go standard library. No runtime dependencies. Static builds for linux/amd64 and linux/arm64.</sub>
</p>
