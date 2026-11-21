# NULQ

**Find the boundary. Understand the exposure.**

A Linux privilege-boundary discovery and evidence-driven security assessment framework written in Go.

---

## What NULQ does

NULQ collects normalized observations about how a Linux system grants authority, evaluates detection rules against those observations, and emits findings that are traceable back to the exact facts that caused them.

**Observation → Relationship → Evaluation → Evidence → Finding**

A writable file is not automatically a privilege escalation path. A writable directory is not automatically a confirmed weakness. Findings reflect the actual evidence and execution context.

NULQ deliberately does not claim to:

- Exploit or execute discovered content
- Assess sudo policy, capabilities, systemd or cron
- Detect exploitability, CVE applicability or binary behaviour
- Modify the assessed system in any way
- Provide comprehensive penetration testing capability

---

## Assessment coverage (verified)

| Rule | Module | Checks |
|---|---|---|
| `NULQ-ID-001` | identity | Group memberships that confer or can obtain elevated authority |
| `NULQ-FS-001` | filesystem | Set-owner-ID executables, with ownership, location and writability context |
| `NULQ-FS-002` | filesystem | World-writable directories without the sticky bit, escalated when on PATH or containing privileged executables |
| `NULQ-FS-003` | filesystem | Empty, relative, or user-writable PATH entries |
| `NULQ-SYS-001` | system | Kernel sysctl hardening baseline |
| `NULQ-SYS-002` | system | Mandatory access control posture (SELinux/AppArmor) |
| `NULQ-PROC-001` | process | Writable-parent detection: executable consumed by a running process with parent-directory permission analysis |

Default filesystem coverage: every usable mount except pseudo filesystems, container storage, snapshot trees and kernel virtual paths. Traversal is bounded per filesystem root by `--max-files` (default 1,000,000). A truncated traversal is reported as partial with a limitation entry, never silently.

---

## How it works

```text
Linux environment
       ├──▶ Collectors: linux.system, linux.identity, linux.filesystem, linux.process
       ├──▶ Normalized observations: closed vocabulary of kinds and attributes
       ├──▶ Immutable observation store: shared by all rules, content-derived IDs
       ├──▶ Detection rules: 8 registered modules, precise Required prerequisites
       ├──▶ Evidence evaluation: every finding cites the observation and field that triggered it
       ├──▶ Aggregation: referential integrity, deduplication, deterministic ordering
       ├──▶ Report model: JSON, JSONL, Markdown, terminal renderers
       └──▶ Structured findings: severity, confidence, explanation, impact, remediation, limitations
```

The observation-first approach means collectors publish typed, immutable observations with a closed vocabulary of kinds and normalised attributes. Rules consume the shared store; a rule that needs new facts gets a new observation kind, not its own traversal.

---

## Installation

NULQ is a single static binary with no runtime dependencies. Go 1.24+ is required to build it.

```bash
make build           # bin/nulq for the host architecture
make release         # dist/nulq-<version>-linux-{amd64,arm64} + SHA256SUMS
make verify          # verify release checksums
```

Cross compilation targets Linux amd64 and arm64 with `CGO_ENABLED=0`.

---

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

Diagnostics go to stderr. Machine-readable output never contains banners, progress output, colour or log records.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The command completed and no failure threshold was met. |
| 1 | Runtime failure (I/O error, cancellation, invalid internal state). |
| 2 | Usage error: unknown flag, module, rule, format or command. |
| 3 | `--fail-on` was set and a finding met or exceeded the threshold. |

---

## Example output

```text
$ nulq scan
NULQ 0.1.0-dev  Linux privilege-boundary assessment

Host      workstation (Arch Linux, kernel 7.3.5-arch1-1, amd64)
Session   unprivileged user
Scan      rpt-4ebd788d4ca4 · 7 rules · 354 observations · 2.9s

MEDIUM   1  LOW      34  INFO     1

LOW   NULQ-FS-001  Privileged executable outside standard system directories
         Resource: /opt/vendor/helper (file)
         Confidence: HIGH · rule NULQ-FS-001 v1.0.0
         ... (findings cite observation IDs and attribute fields)
```

JSON output is sterile: no ANSI, banners, progress or log records. Find each finding's evidence ID in the `evidence` array to trace it back to the exact observation.

---

## Detection model

- **Observation.** A typed, reusable fact about the assessed system. Carries provenance (collector name, collection time). Never contains secrets.
- **Inventory.** A fact that exists; not inherently risky. A SUID binary in a distribution directory is inventory.
- **Suspicious configuration.** A configuration that warrants attention but does not by itself cross a privilege boundary. A world-writable directory on PATH is LOW unless a privileged consumer is demonstrated.
- **Potential exposure.** A relationship that could cross into elevated authority but is not confirmed. A writable parent of a root-owned SUID executable is MEDIUM without observed privileged execution.
- **Evidence-backed privilege-boundary weakness.** A relationship confirmed by direct evidence. A running process executing a replaceable root-owned SUID on a mount without nosuid/noexec is HIGH.

Unknown or incomplete evidence is never treated as confirmed exploitability. When a rule cannot decide, it reports less, not more.

---

## Project status

M2 — **Implementation complete — conditionally accepted.**

All four deliverables are implemented:

- Process observations from `/proc/<pid>` with bounded, race-aware collection
- Mount flag analysis (`nosuid`, `noexec`) as first-class observations
- ACL-aware permission evaluation where POSIX ACLs are readable
- Directory containment analysis (writable parent of a privileged file)

**Outstanding verification conditions:**

- **Docker / Alpine lab E2E and container isolation** — BLOCKED by directive (daemon reachable but deliberately unused). No container was started; no M2-era E2E evidence exists.
- **HIGH-severity live fixture** — A root-owned SUID executable in a writable directory cannot be created unprivileged. The HIGH branch is proven by rule-level synthetic tests; the same pipeline is demonstrated end-to-end at INFO.
- **Lab scenario refresh** — No M2 scenarios or fixtures exist in `lab/manifest.json` (process, acl, nosuid, noexec each occur 0 times). Artifacts are M1.5-era; a refresh depends on Docker.

M3–M7 milestones remain planned as documented in `ROADMAP.md`. The project is not yet fully production-ready or fully audited.

---

## Safety

NULQ is authorised-use software: post-access assessments, hardening reviews, CTF and laboratory environments, and automated security pipelines. It is not an exploitation tool, a persistence tool or a remote-control service.

- **Read-only assessment.** NULQ opens files read-only, never writes to the assessed system, never executes discovered binaries or scripts, and never attempts privilege escalation.
- **No network use.** The scanner makes no network connections and requires no database or interpreter.
- **Unprivileged operation.** Baseline discovery works as an ordinary user. Permission-denied paths are reported as unavailable, not bypassed.
- **Sanitized output.** Control characters from paths, group names and observation values are stripped before terminal and Markdown rendering, so a hostile filesystem cannot inject escape sequences.
- **Deterministic evidence.** Findings cite the observation ID and field that triggered them; evidence carries the collector name and collection time.

Output files are created with mode 0600; treat reports as sensitive.

Link to the full security policy: [SECURITY.md](SECURITY.md).

---

## Documentation and contribution

- [AGENTS.md](AGENTS.md) — engineering constitution with host-protection policy
- [MISSION.md](MISSION.md) — current milestone scope
- [ROADMAP.md](ROADMAP.md) — milestone sequence and acceptance criteria
- [CHANGELOG.md](CHANGELOG.md) — project history
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide
- [docs/architecture.md](docs/architecture.md) — full design
- [docs/decisions/](docs/decisions/) — architecture decision records

This README is independently understandable to a recruiter, security engineer, or open-source contributor who has never seen the codebase.

---

*© 2026 Dustin Oprea. Licensed under the terms described in LICENSE.*