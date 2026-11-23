# NULQ laboratory validation

**Verdict:** FAIL

Generated: 2026-11-22T11:12:20Z

## Environment

| Field | Value |
|---|---|
| Target | Alpine Linux 3.22 (BusyBox), linux/amd64, deliberately misconfigured |
| Image | nulq-vulntarget/alpine-target:3.22 |
| Image ID | sha256:296dfac6a3f40fd1c24a757979f58f732bf069388a1944bd14704f559e95d03f |
| Base image | alpine:3.22 |
| Base digest | sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f |
| NULQ version | nulq 0.1.0-dev |
| Image built at | 2026-11-22T11:08:41Z |
| Container uid | 10001 |

## Summary

| Metric | Value |
|---|---|
| Scenarios total | 25 |
| Passed | 20 |
| Failed | 0 |
| Unsupported | 5 |
| Expected findings | 14 |
| Actual findings | 96 |
| Missing findings | 0 |
| Unexpected findings | 0 |
| Severity mismatches | 0 |
| Confidence mismatches | 0 |
| Scans validated | 5 |
| Scans invalid | 0 |

## Container isolation

| Check | Result | Detail |
|---|---|---|
| assessment runs as a non-root user | PASS | uid=10001 |
| root filesystem is read-only | PASS |  |
| effective capabilities are empty | PASS | CapEff=0000000000000000 |
| no-new-privileges is set | PASS |  |
| no routable network access | PASS | interfaces=bonding_masters,erspan0,gre0,gretap0,ip6_vti0,ip6gre0,ip6tnl0,ip_vti0,lo,sit0,tunl0; routable_v4=0;outbound_connect=blocked |
| Docker socket is absent | PASS |  |
| the mounted nulq binary executes | PASS | /opt/nulq/nulq |
| /tmp is writable and size-limited | PASS |  |
| /tmp refuses execution | PASS |  |

## Scenarios

| ID | Category | Environment | Scan | Status | Findings |
|---|---|---|---|---|---|
| VT-FS-001 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-002 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-003 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-004 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-005 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-006 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-007 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-008 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-009 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-010 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-FS-011 | coverage | synthetic | fixtures | PASSED | 27 |
| VT-PATH-001 | path-hijack | synthetic | path | PASSED | 30 |
| VT-PATH-002 | path-hijack | synthetic | path | PASSED | 30 |
| VT-PATH-003 | path-hijack | synthetic | path | PASSED | 30 |
| VT-PATH-004 | path-hijack | synthetic | path | PASSED | 30 |
| VT-ID-001 | identity | live | identity | PASSED | 1 |
| VT-SGID-001 | filesystem | synthetic | fixtures | PASSED | 27 |
| VT-APP-001 | application | synthetic | fixtures | PASSED | 27 |
| VT-APP-002 | application | synthetic | fixtures | PASSED | 27 |
| VT-APP-003 | application | synthetic | app | PASSED | 11 |
| VT-CAP-001 | capabilities | unsupported | — | UNSUPPORTED | 0 |
| VT-SUDO-001 | sudo | unsupported | — | UNSUPPORTED | 0 |
| VT-CRON-001 | cron | unsupported | — | UNSUPPORTED | 0 |
| VT-SYSTEMD-001 | systemd | unsupported | — | UNSUPPORTED | 0 |
| VT-CONTAINER-001 | container | unsupported | — | UNSUPPORTED | 0 |

## Findings by rule

| Rule | Findings |
|---|---|
| NULQ-FS-001 | 10 |
| NULQ-FS-002 | 22 |
| NULQ-FS-003 | 3 |
| NULQ-ID-001 | 1 |
| NULQ-SYS-001 | 15 |
| NULQ-SYS-006 | 3 |
| NULQ-SYS-007 | 12 |
| NULQ-SYS-008 | 3 |

## Coverage

| Scan | Status | Execution complete | Coverage complete | Files | Directories | Errors | Denied | Truncated roots |
|---|---|---|---|---|---|---|---|---|
| app | complete | true | true | 4 | 4 | 0 | 0 | — |
| baseline | partial | true | false | 112 | 128 | 3 | 3 | — |
| fixtures | partial | true | false | 18 | 33 | 2 | 2 | — |
| identity | complete | true | true | 0 | 0 | 0 | 0 | — |
| path | partial | true | false | 18 | 33 | 2 | 2 | — |

## Scans

| Scan | Report | OS | Duration | Observations | Findings | Schema |
|---|---|---|---|---|---|---|
| app | scan-app.json | alpine | 4 ms | 90 | 11 | valid |
| baseline | scan.json | alpine | 19 ms | 107 | 27 | valid |
| fixtures | scan-fixtures.json | alpine | 7 ms | 106 | 27 | valid |
| identity | scan-identity.json | alpine | 4 ms | 57 | 1 | valid |
| path | scan-path.json | alpine | 11 ms | 108 | 30 | valid |

## Collection errors

- baseline: 3 entries under / could not be traversed (3 permission denied)
- fixtures: 2 entries under /lab/fixtures could not be traversed (2 permission denied)
- path: 2 entries under /lab/fixtures could not be traversed (2 permission denied)

## Unsupported checks

- **VT-CAP-001** (File capability metadata unsupported in lab): Setting real security.capability xattrs on fixture binaries requires capabilities not available in the read-only laboratory image.
- **VT-SUDO-001** (Sudoers policy parsing unsupported in lab): The sudo collector reads /etc/sudoers from the live system, not from --root fixtures.
- **VT-CRON-001** (Cron job inventory unsupported in lab): The cron collector reads system cron directories from the live system, not from --root fixtures.
- **VT-SYSTEMD-001** (systemd unit analysis unsupported in lab): Alpine does not run systemd; no service is started or stopped.
- **VT-CONTAINER-001** (Container runtime configuration unsupported in lab): Deeper container runtime configuration analysis is scheduled for M4; no container escape is attempted.

## Limitations

- Fixture scans (--root /lab/fixtures) assess synthetic objects created at image build time; they are not live operating-system observations.
- Baseline scans mount an empty tmpfs over /lab/fixtures, so fixture findings can never appear as live Alpine observations.
- Alpine/BusyBox cannot represent systemd, PAM, SELinux or distribution package layout; those scenarios are reported as unsupported.
- The container shares the Docker host kernel; sysctl observations describe that kernel, not bare metal.
- Container isolation is proven by inspection and in-container checks, not by kernel auditing.

## Artifacts

- `scan.json` — baseline Alpine assessment
- `scan-fixtures.json` — fixture-root assessment
- `scan-path.json` — hostile PATH assessment
- `scan-identity.json` — wheel-membership assessment
- `isolation.json` — in-container security probe
- `validation.json` — machine-readable validation result
