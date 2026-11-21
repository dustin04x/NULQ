# The Linux privilege model NULQ assesses

This document records the semantics NULQ relies on and where its analysis stops.
Accuracy here matters more than rule count.

## Credentials

A Linux process carries real, effective and saved UID/GID sets, a filesystem
UID/GID, supplementary groups, capabilities and (optionally) an LSM label.
Kernel permission checks use the **effective** credentials. NULQ therefore
evaluates access with the effective UID/GID of its own process, never the real
UID, and records real and effective values separately.

Supplementary groups matter for `EACCES` decisions: a group-writable file is
writable if the process's effective group or any supplementary group matches.

**NULQ records:** UID, EUID, GID, EGID, supplementary group names/IDs, primary
group, umask, namespace identifiers.

**NULQ does not yet record:** capabilities (M3), LSM labels per process (M4).

## Set-owner-ID executables

- **SUID root** (`mode 4755`, owner `root`): execution sets the effective UID
  to root for the process lifetime.
- **SGID** (`mode 2755`, group `tty`): execution sets the effective GID to the
  file's group.
- The bits only matter when the file is executable and the filesystem is
  mounted without `nosuid`.

Presence is an inventory fact, not a vulnerability. A SUID binary is a review
target because its logic, configuration and environment handling run with the
owner's authority. NULQ separates:

| Condition | Severity | Reasoning |
|---|---|---|
| Root-owned and writable by the current user | HIGH | Replacing the file yields root authority |
| Writable by the current user, non-root owner | MEDIUM | Delegated authority and lost integrity control, not root |
| Owned by a non-root account | MEDIUM | Authority is delegated to an unexpected account |
| Outside packaged system paths | MEDIUM | Locally installed privileged code needs review |
| Otherwise | LOW | Inventory; context needed |

Confidence is HIGH for the observed facts. Exploitability is never asserted:
binary logic, linked libraries and configuration consumers are out of scope.

## Directories and PATH

Directory permissions decide who can create, rename and delete entries. A
world-writable directory without the sticky bit allows any local user to
replace files consumed by others. With the sticky bit, only the file owner (or
the directory owner) may delete entries.

PATH resolution searches entries left to right. Dangerous conditions:

- an empty entry, interpreted as the current directory;
- a relative entry, resolved against the working directory;
- a directory writable by the current user but owned by another account.

A user-owned writable PATH directory is normal for developer tooling; it is
LOW, and only matters if a privileged process inherits that PATH. Whether sudo
resets PATH (`secure_path`) is a sudoers question deferred to M3.

**Path handling detail:** on Linux a symlink's own mode is always `0777`, which
is meaningless for access. NULQ resolves PATH entries with `stat(2)` and
records the symlink separately. This prevents the classic false positive where
`/bin` (a symlink to `/usr/bin`) appears world-writable.

## Mounts

Mount options are privilege-boundary modifiers: `nosuid` neutralises SUID
bits, `noexec` blocks execution, `ro` prevents modification. NULQ records these
options as mount observations. Filesystem discovery skips pseudo filesystems,
container storage, snapshot trees and kernel paths; those are either virtual,
duplicated trees, or belong to a later container-aware milestone.

## Sudo (M3)

Sudoers policy determines which commands an account may run as which user,
with which authentication requirements. NULQ will parse policy read-only,
including includes and aliases, and will never invoke `sudo`. Until then, group
membership is reported with an explicit limitation that policy is not evaluated.

## File capabilities (M3)

Capabilities grant a subset of root's authority to a file. Dangerous
assignments include `cap_setuid`, `cap_setgid`, `cap_dac_override`,
`cap_dac_read_search`, `cap_sys_admin`, `cap_sys_ptrace` and
`cap_sys_module`. Presence is not exploitability; NULQ will explain the
specific authority and require contextual evidence.

## systemd and scheduled execution (M3)

A unit's `User=`, `ExecStart=` and referenced paths form an execution
dependency chain. The security question is not "is this file writable?" but
"can an unprivileged account modify something a privileged unit executes?".
The same reasoning applies to cron files, run-parts directories and timers.

## Containers and namespaces (M4)

Namespace identifiers reveal isolation, not safety. Membership in `docker`,
`podman`, `lxd` or `libvirt` groups is reported now because those memberships
typically grant host-root-equivalent control through daemons. Container escape
analysis is explicitly out of scope; NULQ never attempts it.

## Kernel hardening controls

`NULQ-SYS-001` encodes a conservative baseline:

| Parameter | Baseline | Why |
|---|---|---|
| `kernel.kptr_restrict` | ≥ 1 | Kernel pointer disclosure aids exploitation |
| `kernel.dmesg_restrict` | 1 | Ring buffer can expose addresses |
| `kernel.yama.ptrace_scope` | ≥ 1 | Limits cross-process tracing |
| `kernel.perf_event_paranoid` | ≥ 2 | Restricts unprivileged sampling |
| `kernel.unprivileged_bpf_disabled` | ≥ 1 | Unprivileged BPF has been an LPE source |
| `kernel.randomize_va_space` | 2 | Full ASLR |
| `kernel.suid_dumpable` | 0 | Core dumps of SUID processes leak memory |
| `fs.protected_hardlinks` | 1 | Blocks link-following attacks on privileged writers |
| `fs.protected_symlinks` | 1 | Blocks symlink attacks in sticky directories |
| `fs.protected_fifos` / `fs.protected_regular` | ≥ 1 | Blocks planted-file attacks |
| `kernel.unprivileged_userns_clone` | 0 (where present) | Widens kernel surface |

A deviation is a hardening gap (LOW or INFO), never a vulnerability claim. An
absent knob is skipped, not assumed secure.

## Mandatory access control

SELinux and AppArmor confine processes even after they gain elevated
credentials. NULQ checks whether a MAC module is advertised and enforcing.
Permissive SELinux is MEDIUM because it provides no denial. Missing MAC is LOW
with MEDIUM confidence, because profile coverage is beyond this check. Landlock
and Yama are not MAC modules and do not satisfy the baseline.

## Explicit non-claims

- No kernel-version-to-exploit mapping. Version alone never establishes
  exploitability.
- No binary analysis, no fuzzing of discovered binaries, no exploitation.
- No ACL evaluation in v0.1.0: mode bits only, documented in every affected
  finding.
