# NULQ

A read-only Linux privilege-boundary discovery and evidence-driven security
assessment framework, written in Go.

**Find the boundary. Understand the exposure.**

NULQ answers one question precisely: how does this Linux system grant
authority, and what evidence supports that claim?

It collects normalized observations about users, groups, processes, filesystems,
mounts, capabilities, sudoers policy, cron jobs, systemd units, SSH
configuration, containers, namespaces, and kernel mitigations — then evaluates
detection rules against those observations and emits findings traceable back to
the exact facts that caused them.

NULQ is **read-only**: it opens files read-only, never executes discovered
binaries or scripts, never starts or stops services, never modifies the assessed
system, and makes no network connections. It is authorised-use software for
post-access assessments, hardening reviews, CTF and laboratory environments, and
automated security pipelines. It is not an exploitation tool, a persistence
tool, or a remote-control service.

---

## Capabilities

| Domain | Rules | What they detect |
|--------|-------|------------------|
| Identity | `NULQ-ID-001`–`ID-004`, `NULQ-ID-006` | Privileged group membership, sudoers policy, cron jobs, non-root UID-0 accounts, writable SSH `authorized_keys` |
| Filesystem | `NULQ-FS-001`–`FS-005` | SUID/SGID executables, world-writable directories, unsafe PATH entries, mount flag constraints, file capabilities |
| Process | `NULQ-PROC-001` | Writable parent directory of an executable consumed by a running process |
| System | `NULQ-SYS-001`–`SYS-009` | Kernel sysctl hardening, MAC posture, process capabilities, seccomp, systemd unit hardening, user namespaces, kernel mitigations, container indicators, sshd configuration |

Run `nulq rules list --format json` for full rule metadata.

> Rule ID `NULQ-ID-005` is not registered in `0.1.0-dev`; the identity sequence
> is not contiguous. Do not interpret a gap in IDs as an unimplemented check
> within a contiguous range.

---

## Installation

NULQ is a single static binary with no runtime dependencies. Go **1.24.0+** is
required to build.

```bash
# Clone
git clone https://github.com/dustin04x/NULQ.git
cd NULQ

# Build for the host architecture
make build

# Inspect version metadata
./bin/nulq version

# Cross-compile for linux/amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/nulq

# Cross-compile for linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq
```

Release artifacts (with SHA-256 checksums) are produced via `make release`.
Published binaries are not yet available; build from source.

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

# Exit 3 when any finding at MEDIUM or above exists
nulq scan --fail-on medium

# List registered rules
nulq rules list

# Show collected system facts
nulq system info

# Print build metadata
nulq version

# Manage saved reports (scan persists by default; --save=false disables)
nulq report list
nulq report show <report-id>
nulq report export <report-id> --format json
nulq report export <report-id> --format sarif

# Manage named baselines and differential comparison
nulq baseline create <name> --report <report-id>
nulq baseline list
nulq baseline compare <name> --report <report-id>
```

Diagnostics go to **stderr**. Machine-readable output never contains banners,
progress output, colour, or log records.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no failure threshold met |
| `1` | Runtime failure (I/O error, cancellation, invalid internal state) |
| `2` | Usage error (unknown flag, module, rule, format, command) |
| `3` | `--fail-on` set and a finding met or exceeded the threshold |

---

## Output formats

| Format | Use |
|--------|-----|
| `terminal` | Human-readable report with optional colour (default) |
| `json` | Structured JSON report, schema version 1.1 |
| `jsonl` | JSON Lines, one object per line |
| `markdown` | Markdown report for documentation and sharing |
| `sarif` | SARIF 2.1.0 export for security tooling (`scan` and `report export`) |

By default every `scan` persists the report to local storage
(`--save`, default `true`) under `~/.local/share/nulq/reports`; use
`--data-dir` to override the directory and `--save=false` to disable persistence.

Reports are sensitive — they can contain host configuration details — and output
files are created with mode `0600`.

---

## Findings and evidence

Every finding carries:

- A stable identifier derived from the rule, affected resource, and title
- The rule ID and version
- Severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and confidence
- The affected resource and resource kind
- Evidence references that resolve to observation IDs
- Technical explanation, impact, remediation guidance, and limitations
- References where applicable

Presence is not vulnerability. A SUID binary in a distribution directory is
inventory; a writable PATH entry is LOW unless a privileged consumer is
demonstrated. Unknown or incomplete evidence is never treated as confirmed
exploitability, and missing evidence is not equivalent to evidence that a
condition is absent.

---

## Differential analysis

NULQ supports named baselines created from saved reports. Comparing an
assessment against a baseline classifies each finding as:

- **new** — exists only in the current report
- **resolved** — exists only in the baseline
- **unchanged** — exists in both reports without relevant changes
- **changed** — exists in both reports but severity, confidence, or evidence differs

An incomplete current scan must not falsely resolve a previous finding. If a
module is missing, collection is permission-restricted, or coverage has
decreased, affected comparisons are marked **unresolved** with a warning rather
than silently classified as resolved.

```bash
nulq baseline create <name> --report <report-id>
nulq baseline compare <name> --report <report-id>
```

---

## Reporting

NULQ emits JSON (schema version 1.1), JSONL, Markdown, and SARIF 2.1.0. SARIF
is suitable for import into security tooling; JSON remains the primary contract
because it expresses NULQ's evidence provenance cleanly.

---

## Security model and limitations

NULQ is a read-only assessment tool:

- Files are opened read-only; nothing on the assessed system is modified.
- No discovered binaries or scripts are executed.
- No services are started, stopped, or reconfigured.
- No network connections are made.
- Output is sanitized: control characters from paths, group names, and
  observation values are stripped before terminal and Markdown rendering.
- Persisted reports and baselines use restrictive permissions, atomic writes,
  symlink refusal, and path-traversal guards.

Storage is not immune to a malicious local user who controls the data
directory; persisted reports are treated as untrusted input on load.

Known limitations:

- POSIX ACLs are evaluated for effective read/write/execute decisions in
  replaceability checks when normalized ACL state is readable. Unreadable or
  malformed ACLs are treated as unknown and never fall back to an unsafe
  mode-bit claim. MAC policy is reported as module presence/enforcement only
  (`NULQ-SYS-002`), not as a full policy audit.
- `sudo`, capabilities, and cron rules are implemented and unit-tested; the
  systemd rule and collector are implemented but lack dedicated unit tests.
  None of these domains is exercised against a live Alpine target, so they
  appear as unsupported lab scenarios on that target.
- Docker is a prerequisite for the laboratory and is not installed by this
  project.
- The laboratory runs on a pinned Alpine container; it cannot represent
  systemd, PAM, SELinux, or distribution package layout. Those checks are
  synthetic fixtures or unsupported scenarios.

### Laboratory results

The isolated Docker laboratory builds the real binary, executes it unprivileged
inside a pinned Alpine container, validates every report against the published
JSON schema, and evaluates the scenario manifest:

- 34/34 supported scenarios passed
- 5 unsupported scenarios reported explicitly, never as passes
- 0 missing findings, 0 unexpected findings, 0 invalid scans
- 5/5 reports schema-valid

The 5 unsupported scenarios are capabilities, sudo, systemd, cron, and
container runtime. Their rules are implemented, but the Alpine laboratory
cannot exercise them: the collectors read live system paths or need privileges
unavailable in the read-only container, and deeper container-runtime analysis
is not implemented. Unsupported is reported explicitly, never as a pass.

---

## Development and testing

```bash
gofmt -l .          # must be empty
go vet ./...        # static analysis
go test ./...       # unit and integration tests
go test -race ./... # race detector clean
make build          # host binary
make lab-test       # Docker laboratory: 34/34 scenarios pass, 5 unsupported
```

Parser fuzz targets exist for `/etc/passwd`, `/etc/group`, `/etc/os-release`,
mountinfo, and ACL parsing. Bounded fuzz campaigns complete without panics;
fuzzing is not exhaustive and does not prove the absence of vulnerabilities.

---

## Documentation

- [`AGENTS.md`](AGENTS.md) — engineering constitution and host-protection policy
- [`MISSION.md`](MISSION.md) — current mission and laboratory acceptance criteria
- [`ROADMAP.md`](ROADMAP.md) — milestone history and completion status
- [`SECURITY.md`](SECURITY.md) — security policy, threat model, and limitations
- [`CHANGELOG.md`](CHANGELOG.md) — release history
- [`docs/json-schema.md`](docs/json-schema.md) — report schema contract
- [`docs/architecture/`](docs/architecture/) — architecture, severity model, lab architecture
- [`docs/testing/`](docs/testing/) — scenario design and Docker security model
- [`lab/README.md`](lab/README.md) — laboratory operation and isolation

---

## License

MIT. See [LICENSE](LICENSE).

---

<sub>Built with the Go standard library. No runtime dependencies. Static builds
for linux/amd64 and linux/arm64.</sub>
