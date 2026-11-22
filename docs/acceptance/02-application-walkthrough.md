# Phase Two: Complete Application Walkthrough

**Recorded:** 2026-11-22T09:41:00Z  
**Binary:** `bin/nulq 0.1.0-dev` (commit c278284, linux/amd64)  
**Host:** Arch Linux, uid 1000, unprivileged  

## CLI entry points tested

| Command | Exit code | Output | Notes |
|---------|-----------|--------|-------|
| `nulq version` | 0 | Version, commit, build date, Go, platform | Prints to stdout |
| `nulq system info` | 0 | Hostname, distro, kernel, LSM, sysctl, execution context | No secrets leaked |
| `nulq rules list` | 0 | 20 rules in tabular format | `--format json` also available |
| `nulq scan --format json` | 0 | 1044 findings, coverage object, valid JSON | 7.6s duration |
| `nulq scan --format terminal` | 0 | Human-readable terminal output | No ANSI in machine modes |
| `nulq scan --format markdown` | 0 | Markdown report | Sanitized output |

## Rules registered (20)

```
NULQ-FS-001  filesystem  INFO      Set-owner-ID executable inventory
NULQ-FS-002  filesystem  MEDIUM    Directory writable by the assessed user without adequate entry protection
NULQ-FS-003  filesystem  LOW       Unsafe PATH directory
NULQ-FS-004  filesystem  INFO      Mount flag constrains or exposes privileged executable behavior
NULQ-FS-005  filesystem  LOW       File capability inventory
NULQ-ID-001  identity    LOW       Privileged group membership
NULQ-ID-002  identity    LOW       Sudoers policy inventory
NULQ-ID-003  identity    LOW       Cron job inventory
NULQ-ID-004  identity    HIGH      Non-root UID-0 accounts
NULQ-ID-006  identity    MEDIUM    Writable SSH authorized_keys files
NULQ-PROC-001 process    MEDIUM    Executable consumed by a running process is replaceable in its parent directory
NULQ-SYS-001 system      LOW       Kernel sysctl hardening baseline
NULQ-SYS-002 system      LOW       Mandatory access control posture
NULQ-SYS-003 system      INFO      Process capability surface
NULQ-SYS-004 system      INFO      Seccomp profile presence
NULQ-SYS-005 system      LOW       Systemd unit lacks security hardening directives
NULQ-SYS-006 system      INFO      Unprivileged user namespace clone enabled
NULQ-SYS-007 system      INFO      Kernel hardware vulnerability mitigations
NULQ-SYS-008 system      INFO      Container runtime indicators
NULQ-SYS-009 system      MEDIUM    SSH daemon configuration hardening
```

## Scan output structure

JSON report contains:
- `schema_version`: "1.1"
- `tool`: name, version, commit, build_date, go_version, platform
- `host`: hostname, os_id, os_name, kernel_release, architecture, container, security_modules
- `scan`: report_id, started_at, finished_at, duration_ms, modules, scan_roots, unprivileged, partial
- `coverage`: status (partial/complete), execution_complete, coverage_complete, files_examined, directories_examined, traversal_errors, permission_denied, unavailable_observations, unsupported_observations, truncated_roots, excluded_roots, skipped_rules, failed_operations, roots[]
- `findings[]`: id, rule_id, rule_version, title, description, category, severity, confidence, resource, resource_kind, evidence[], explanation, impact, remediation, limitations[], detected_at

## Coverage honesty

Coverage distinguishes `execution_complete` (true — all roots traversed) from
`coverage_complete` (false — some roots had permission denials). Permission
denials are counted per root, not swallowed. Excluded roots (proc, sys, dev,
docker overlayfs) are listed separately from traversal failures.

## Host protection

Binary ran as uid 1000, unprivileged. No root required. No writes to the
assessed system. Read-only inspection only.

## No defects found

All CLI entry points produce correct output. Scan completes with valid JSON.
Coverage reporting is honest (execution_complete != coverage_complete).
