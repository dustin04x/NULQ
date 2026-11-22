# Phase Six: Rule-by-Rule Adversarial Validation

**Recorded:** 2026-11-22T09:45:00Z  
**Scope:** All 20 registered rules  

## Validation method

Each rule was reviewed for: correct Required observation kinds, proper
unavailable-data handling (skip, not approximate), severity not inflated
(presence ≠ vulnerability), evidence-backed claims, limitations stated, and
no false positives from unknown states.

## Rule-by-rule results

| Rule | ID | Severity | Required kinds | Unavailable handling | Status |
|------|-----|----------|----------------|---------------------|--------|
| Set-owner-ID executable inventory | NULQ-FS-001 | INFO | filesystem.file | Skip if no files | Certified |
| World-writable dir without sticky | NULQ-FS-002 | MEDIUM | filesystem.directory | Skip if no dirs | Certified |
| Unsafe PATH directory | NULQ-FS-003 | LOW | filesystem.path_entry | `unknown` writability → skip (fixed A-001) | Certified |
| Mount flag constrains privileged exec | NULQ-FS-004 | INFO | filesystem.file, mount | Skip if no mounts | Certified |
| File capability inventory | NULQ-FS-005 | LOW | filesystem.file | Skip if no caps | Certified |
| Privileged group membership | NULQ-ID-001 | LOW | identity.execution_context | Skip if no context | Certified |
| Sudoers policy inventory | NULQ-ID-002 | LOW | identity.sudo_rule | Skip if no sudoers | Certified |
| Cron job inventory | NULQ-ID-003 | LOW | identity.cron_job | Skip if no cron | Certified |
| Non-root UID-0 accounts | NULQ-ID-004 | HIGH | identity.user_account | Skip if no passwd | Certified |
| Writable SSH authorized_keys | NULQ-ID-006 | MEDIUM | identity.ssh_authorized_keys | Skip if no keys | Certified |
| Executable replaceable in parent dir | NULQ-PROC-001 | MEDIUM | filesystem.file, process | Skip if no processes | Certified |
| Kernel sysctl hardening | NULQ-SYS-001 | LOW | system.sysctl | Skip if no sysctls | Certified |
| MAC posture | NULQ-SYS-002 | LOW | system.security_control | Skip if no LSM | Certified |
| Process capability surface | NULQ-SYS-003 | INFO | system.process_capability | Skip if no caps | Certified |
| Seccomp profile presence | NULQ-SYS-004 | INFO | system.seccomp | Skip if unavailable | Certified |
| Systemd unit hardening | NULQ-SYS-005 | LOW | system.systemd_unit | Skip if no units | Certified |
| Unprivileged user namespace clone | NULQ-SYS-006 | INFO | system.sysctl | Skip if sysctl unavailable | Certified |
| Kernel hardware mitigations | NULQ-SYS-007 | INFO | system.kernel_mitigation | Skip if /sys unavailable | Certified |
| Container runtime indicators | NULQ-SYS-008 | INFO | system.container_indicator | Skip if no indicators | Certified |
| SSH daemon hardening | NULQ-SYS-009 | MEDIUM | system.sshd_config | Skip if config absent | Certified |

## Adversarial checks

| Check | Result |
|-------|--------|
| `writable == "unknown"` not reported as writable | Pass (fixed A-001) |
| Presence of SUID bit without execute bit not treated as vulnerability | Pass (FS-001, FS-004) |
| World-writable dir only escalates for directly replaceable root-owned SUID | Pass (FS-002) |
| User-owned sticky directory not reported | Pass (FS-002) |
| PATH writability is LOW without observed privileged consumer | Pass (FS-003) |
| No rule reads filesystem, spawns processes, or prints | Pass (collectors only) |
| No rule assigns severity to collector data | Pass (rules interpret, collectors observe) |
| All rules have Required kinds; engine skips missing prerequisites | Pass |

## No defects found

All 20 rules pass adversarial validation. No false positives from unknown
states, no severity inflation, all findings evidence-backed.
