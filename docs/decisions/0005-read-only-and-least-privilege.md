# 0005 — Read-only operation and least privilege

- Status: accepted
- Date: 2026-11-21

## Context

NULQ runs inside environments where a mistake is expensive: production hosts,
red-team labs, CTF infrastructure and automated pipelines. Tools that "verify"
a finding by exploiting it, or that quietly request root, are unacceptable.

## Decision

- NULQ never writes to the assessed system, starts/stops services, changes
  permissions, creates accounts, or executes discovered binaries or scripts.
- It never invokes `sudo`, `su` or set-owner-ID binaries.
- It never attempts privilege escalation or persistence.
- Baseline collection works as an ordinary user. Unreadable resources become
  `unavailable` observations with a class; they are never bypassed.
- NULQ spawns no subprocesses at all in v0.1.0, removing command-injection and
  PATH-hijack risk from its own execution.
- Output files are created with mode 0600.

## Consequences

Positive:

- Safe to run on production systems during an assessment window.
- Safe to run automatically without an approval gate for state changes.
- The tool cannot become the exploit path it is meant to find.

Negative:

- Coverage is lower unprivileged: some trees and kernel knobs are unreadable.
  This is reported rather than worked around.
- Some checks that would require executing a program (for example, `sudo -l`)
  are deferred or implemented by parsing configuration instead.
- A privileged opt-in mode may be useful later for root-owned fixtures; it would
  have to preserve the no-write guarantee and remain explicitly documented.

## Alternatives considered

- **Invoke existing utilities (`find`, `getcap`, `systemctl`)**: violates the
  portability and minimal-dependency requirements and inherits their parsing
  and PATH risks.
- **Auto-elevate with sudo**: violates least privilege and destroys operator
  trust.
- **Exploit discovered weaknesses to confirm them**: explicitly out of scope.
