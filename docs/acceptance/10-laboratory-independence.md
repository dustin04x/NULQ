# Phase Ten: Laboratory Independence

**Recorded:** 2026-11-22T09:49:00Z  

## Laboratory architecture

The lab builds the real NULQ binary and executes it unprivileged inside a
minimal Alpine 3.22 container. It validates reports against the published JSON
Schema, evaluates scenario expectations, and cleans up only its own resources.

## Container security baseline (identical for every service)

| Property | Value |
|----------|-------|
| User | non-root uid/gid 10001 |
| Capabilities | cap_drop: ALL |
| no-new-privileges | true |
| Root filesystem | read-only |
| /tmp | noexec,nosuid,nodev, size-limited |
| Network | network_mode: none |
| Host namespaces | none |
| Docker socket | not mounted |
| Bind mounts | read-only bin/nulq only |
| Resource labels | NULQ-labelled for targeted cleanup |

## Lab test results

Two consecutive runs: 34/34 scenarios passed, 5 unsupported, 0 missing,
0 unexpected, 0 invalid scans. All 5 reports schema-valid under both Go
validator and Python jsonschema.

## Scenario coverage

| Scan type | Coverage | Denials | Notes |
|-----------|----------|---------|-------|
| Baseline (full Alpine) | partial | 1 (/root) | /root inaccessible to uid 10001 |
| Fixtures (synthetic root) | partial | 3 | Deliberately denied paths |
| PATH (hostile PATH entries) | partial | 3 | PATH-specific denials |
| Identity (wheel membership) | complete | 0 | Full access |
| Discovery (auto-discovered mounts) | partial | 1 | /proc, /sys excluded |

Unsupported categories are reported as **unsupported** scenarios, never as
passes. Coverage distinguishes `execution_complete` (true) from
`coverage_complete` (false).

## Lab independence

- The lab validates the **real binary**, not a reimplementation
- Docker is a prerequisite, not installed by the project
- No host modifications: no sudo, no package installs, no sysctl changes
- Lab cleanup removes only NULQ-labelled containers, networks, images
- No global Docker prune or volume prune

## No defects found

The laboratory correctly validates the real binary in an isolated container.
All scenario expectations are explicitly judged, not inferred from exit code.
