# NULQ

**Find the boundary. Understand the exposure.**

A read-only Linux privilege-boundary discovery and evidence-driven security
assessment framework written in Go. Standard library only, no dependencies.

## What NULQ does

NULQ collects normalized observations about how a Linux system grants
authority, evaluates detection rules against those observations, and emits
findings traceable back to the exact facts that caused them.

NULQ deliberately does not:

- Exploit or execute discovered content
- Modify the assessed system in any way
- Detect exploitability, CVE applicability or binary behaviour
- Provide comprehensive penetration testing capability

## Assessment coverage (verified)

| Rule | Module | Checks |
|---|---|---|
| `NULQ-ID-001` | identity | Group memberships that confer elevated authority |
| `NULQ-ID-002` | identity | Sudoers policy inventory (passwordless/root execution rules) |
| `NULQ-ID-003` | identity | Cron job inventory (writable job files, scheduled commands) |
| `NULQ-ID-004` | identity | Non-root accounts with UID 0 (root authority) |
| `NULQ-ID-006` | identity | Writable SSH authorized_keys files (public-key injection risk) |
| `NULQ-FS-001` | filesystem | Set-owner-ID / set-group-ID executables, with writability context |
| `NULQ-FS-002` | filesystem | World-writable directories without the sticky bit |
| `NULQ-FS-003` | filesystem | Empty, relative, or user-writable PATH entries |
| `NULQ-FS-004` | filesystem | Mount flags (`nosuid`, `noexec`) constraining privileged executables |
| `NULQ-FS-005` | filesystem | File capability inventory (`security.capability` xattr) |
| `NULQ-SYS-001` | system | Kernel sysctl hardening baseline |
| `NULQ-SYS-002` | system | Mandatory access control posture (SELinux/AppArmor) |
| `NULQ-SYS-003` | system | Process capability surface (privilege-bypassing effective capabilities) |
| `NULQ-SYS-004` | system | Seccomp filter mode per process |
| `NULQ-SYS-005` | system | systemd unit files (User=, ExecStart=, writable dependencies) |
| `NULQ-SYS-006` | system | Unprivileged user namespace clone (`kernel.unprivileged_userns_clone`) |
| `NULQ-SYS-007` | system | Kernel hardware vulnerability mitigations (Spectre, Meltdown, etc.) |
| `NULQ-SYS-008` | system | Container runtime indicators (Docker socket, marker files) |
| `NULQ-SYS-009` | system | SSH daemon configuration (PermitRootLogin, PasswordAuthentication, X11Forwarding) |
| `NULQ-PROC-001` | process | Writable-parent detection: executable consumed by a running process |

Default filesystem coverage: every usable mount except pseudo filesystems
(`/proc`, `/sys`, `/dev`, `/run`), container storage, snapshot trees and
kernel virtual paths. Traversal is bounded per filesystem root by
`--max-files` (default 1,000,000); truncated traversal is reported as
partial, never silently.

## How it works

Collectors publish typed, immutable observations with a closed vocabulary
of kinds and attributes. Rules consume a shared store; a rule that needs
new facts gets a new observation kind, not its own traversal. Every
finding cites the observation ID and field that triggered it.

```
Collectors → Observation store → Rules → Evidence → Findings
```

## Installation

NULQ is a single static binary with no runtime dependencies. Go 1.24+
is required to build it.

```bash
make build           # bin/nulq for the host architecture
make release         # dist/nulq-<version>-linux-{amd64,arm64} + SHA256SUMS
make verify          # verify release checksums
```

Cross-compile for Linux amd64 and arm64 with `CGO_ENABLED=0`.

## Quick start

```bash
nulq --help                                       # show CLI reference
nulq scan                                         # terminal report
nulq scan --format json --output report.json       # JSON report
nulq scan --modules identity,filesystem,process   # module selection
nulq scan --rules NULQ-FS-001,NULQ-PROC-001      # rule selection
nulq rules list                                    # registered rules and metadata
nulq system info                                   # collected platform facts
nulq version                                       # tool version
```

Diagnostics go to stderr. Machine-readable output never contains banners,
progress output, colour or log records.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; no failure threshold met |
| 1 | Runtime failure (I/O error, cancellation, invalid internal state) |
| 2 | Usage error (unknown flag, module, rule, format, command) |
| 3 | `--fail-on` was set and a finding met or exceeded the threshold |

## Laboratory validation

NULQ ships with an isolated Alpine Linux 3.22 laboratory (`lab/`) that
executes the real binary against synthetic fixtures, validates JSON
against the published schema, and evaluates scenarios across identity,
filesystem, path-hijack, system and coverage domains.

```bash
make lab-build    # build the binary and pinned Alpine target image
make lab-test     # isolation probe, scans, schema validation, scenarios
```

Result: **PASS — 34/34 scenarios passed, 5 unsupported (scheduled M3/M4),
0 missing findings, 0 unexpected, 0 invalid scans.**

## Detection model

- **Observation.** A typed, reusable fact about the assessed system. Never contains secrets.
- **Inventory.** A fact that exists; not inherently risky. A SUID binary in a distribution directory is inventory.
- **Suspicious configuration.** A configuration warranting attention but not crossing a privilege boundary by itself.
- **Potential exposure.** A relationship that could cross into elevated authority but is not confirmed.
- **Evidence-backed weakness.** A relationship confirmed by direct evidence.

Unknown or incomplete evidence is never treated as confirmed exploitability.
When a rule cannot decide, it reports less, not more.

## Project status

**Current milestone: M2 complete — all verification gates pass.**

- Unit + integration tests: `go test ./...` pass (race detector clean)
- `gofmt` clean, `go vet` clean
- Binary builds: linux/amd64 and linux/arm64 (`CGO_ENABLED=0`)
- Docker/Alpine lab: `make lab-test` passes (34/34 scenarios, 5 unscheduled M3/M4)

20 rules across identity, filesystem, process, system and SSH domains.
9 collectors (system, identity, filesystem, process, sudo, cron,
container, systemd, sshd).

M3–M7 milestones remain planned as documented in `ROADMAP.md`.

## Safety

NULQ is authorised-use software: post-access assessments, hardening
reviews, CTF and laboratory environments, and automated security
pipelines. It is not an exploitation tool, a persistence tool or a
remote-control service.

- **Read-only.** Opens files read-only; never writes, executes discovered
  content, or attempts privilege escalation.
- **No network.** Makes no network connections; requires no database or interpreter.
- **Unprivileged operation.** Works as an ordinary user. Permission-denied
  paths are reported as unavailable, not bypassed.
- **Sanitized output.** Control characters are stripped before terminal and
  Markdown rendering, so a hostile filesystem cannot inject escape sequences.
- **Deterministic evidence.** Findings cite the observation ID and field that
  triggered them.

Output files are created with mode 0600; treat reports as sensitive.
Full security policy: [SECURITY.md](SECURITY.md).

## Documentation and contribution

- [AGENTS.md](AGENTS.md) — engineering constitution with host-protection policy
- [MISSION.md](MISSION.md) — current milestone scope
- [ROADMAP.md](ROADMAP.md) — milestone sequence and acceptance criteria
- [CHANGELOG.md](CHANGELOG.md) — project history
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide
- [docs/architecture.md](docs/architecture.md) — full design
- [docs/decisions/](docs/decisions/) — architecture decision records

*© 2026 Dustin Oprea.*
