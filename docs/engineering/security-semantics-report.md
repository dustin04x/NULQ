# Security Semantics Report — NULQ

This report documents NULQ's security model, privilege boundary assumptions,
and the semantic guarantees each detection rule provides. It is written for a
reviewer who will not re-run the scan.

## 1. Read-only invariant

NULQ never modifies the assessed system. It never starts, stops, enables, or
disables services. It never executes discovered binaries or scripts. It never
attempts privilege escalation, persistence, or exploitation. All file access
is read-only; unreadable paths are reported as unavailable, never bypassed.

## 2. Privilege model

NULQ models authority from kernel semantics:

- Real vs effective credentials (UID/EUID/GID/EGID from /proc/<pid>/status)
- File mode bits including setuid, setgid, sticky
- POSIX ACLs (parsed and normalized, raw xattrs never stored)
- Capabilities (CapEff, CapBnd from /proc/<pid>/status)
- Seccomp mode
- Mount flags (nosuid, noexec, nodev, ro, rw from /proc/self/mountinfo)
- Namespaces (mount, pid, net, user, ipc, uts, cgroup)
- LSM modules (from system info)
- Systemd unit security directives (from unit files, never via D-Bus)

NULQ distinguishes what the kernel enforces from what a distribution happens
to configure. It does not infer exploitability from version strings or file
presence.

## 3. Severity semantics

Severity states the significance of the observed relationship; confidence
states how well the evidence supports it. They are deliberately separate.

- **INFO**: Inventory-level observation (e.g., setuid binary in standard system directory)
- **LOW**: Weak or contextual weakness (e.g., SUID owned by non-root, non-sticky world-writable dir)
- **MEDIUM**: Meaningful weakness with constraints (e.g., writable PATH entry, privileged executable on mount without nosuid)
- **HIGH**: Direct privilege boundary crossing (e.g., root-owned SUID executable writable by assessed user, running privileged process with replaceable executable)
- **CRITICAL**: Reserved for relationships that plausibly cross into root-equivalent authority with evidence at hand

Presence is not vulnerability. A SUID binary in /usr/bin is inventory (INFO).
A writable PATH entry is LOW unless a privileged consumer is demonstrated.

Only a privileged executable **directly inside** a world-writable directory is
replaceable through that directory; nested files are not escalated to HIGH.
A set-owner-ID bit without an execute bit is inert.

## 4. Rule-by-rule semantics

### NULQ-IDENT-001 (Privileged group membership)
- **What it detects**: Membership in groups that confer elevated authority
  (docker, wheel, sudo, root, adm).
- **Severity**: HIGH for docker (container escape = host root), LOW for
  wheel/sudo/root/adm (traditional privilege escalation groups).
- **Limitation**: Group membership alone does not confer authority; the user
  must also authenticate or have passwordless sudo. Unknown groups are not
  guessed at.

### NULQ-FS-001 (Set-owner-ID executable inventory)
- **What it detects**: Files with setuid or setgid bits.
- **Severity**: Contextual. INFO for standard system paths (/usr/bin,
  /bin). LOW for non-standard paths, non-root owners, non-executable files.
  HIGH for root-owned writable by current user.
- **Limitation**: Does not evaluate whether the binary is actually
  reachable or executable in context. Setuid without execute bit is inert.

### NULQ-FS-002 (World-writable directory)
- **What it detects**: Directories writable by the assessed user without
  adequate entry protection (no sticky bit, or sticky owned by assessed user).
- **Severity**: MEDIUM for non-sticky world-writable dirs. HIGH when a
  privileged executable is a direct child. MEDIUM when PATH membership alone
  is the only factor.
- **Limitation**: PATH membership alone does not escalate; a privileged
  consumer must be demonstrated. Nested privileged executables do not
  escalate beyond MEDIUM.

### NULQ-FS-003 (PATH entry)
- **What it detects**: PATH entries that are empty, relative, writable,
  or missing.
- **Severity**: LOW for all problematic entries.
- **Limitation**: Missing entries produce no finding. Non-writable,
  non-relative, existing entries produce no finding.

### NULQ-FS-004 (Mount flags)
- **What it detects**: Setuid executables on mounts without nosuid;
  world-writable directories on mounts without noexec.
- **Severity**: INFO — mount flags constrain execution semantics; they are
  never reported as escalation by themselves.
- **Limitation**: Mount flags are object-dependent. nosuid affects SUID/SGID
  semantics; noexec affects direct execution. Neither prevents read access.

### NULQ-PROC-001 (Writable parent / replaceable executable)
- **What it detects**: Running processes whose executable is replaceable by
  the assessed user (writable parent directory, ACL grant, missing sticky
  protection), especially when the executable is privileged (setuid/setgid)
  or the process runs with elevated credentials.
- **Severity**: Contextual from INFO (unprivileged executable) to HIGH
  (running privileged process executing replaceable privileged executable).
- **Limitation**: ACL state may be unavailable or malformed. Mount metadata
  may be absent. Process identity may be stale. Inconsistent observations
  across processes produce LOW confidence findings.

### NULQ-SYS-001 (Sysctl hardening)
- **What it detects**: Kernel parameters below secure baselines
  (e.g., kernel.kptr_restrict = 0, kernel.dmesg_restrict = 0).
- **Severity**: LOW for each weak parameter.
- **Limitation**: Unreadable parameters are reported as unavailable, never
  assumed weak or strong. Baselines are conservative defaults, not
  distribution-specific requirements.

### NULQ-SYS-002 (MAC / LSM controls)
- **What it detects**: Missing or permissive Mandatory Access Control
  (AppArmor, SELinux, etc.).
- **Severity**: LOW for missing control, MEDIUM for permissive SELinux.
- **Limitation**: Advertised but unobserved LSM state is unknown, not
  disabled. No finding is claimed for unknown state. Enforcing AppArmor
  alongside permissive SELinux produces only the permissive finding.

### NULQ-SYS-003 through NULQ-SYS-006 (M4 additions)
- **Capabilities**: Effective/bounding capability analysis
- **Seccomp**: Seccomp mode observation
- **Systemd**: Unit security directive analysis
- **Userns**: User namespace analysis
- These rules follow the same evidence-backed, limitation-stated pattern.

## 5. Evidence provenance

Every finding cites at least one evidence item. Evidence IDs are
content-derived (SHA-256 of observation ID + field), so duplicate references
collapse. Evidence never contains secrets: no file contents, passwords,
tokens, or keys. Every value originating in the assessed system passes
through `internal/reporting` sanitizers before terminal or Markdown output.

## 6. Correlation

Correlation (COR-001 through COR-005) is implemented as a design artifact
(M3) but is explicitly not finding-generating per M10 constraints. It does
not describe NULQ as correlating, graphing, or chaining findings. No finding
depends on an inferred edge.

## 7. Error handling

All failures are wrapped in classified error classes:
permission_denied, not_found, unavailable, unsupported, malformed_input,
timeout, canceled, resource_exhausted, internal. Unavailability is data,
not an error to swallow. Rules that lack data are skipped with a reason;
collectors that fail are published as failed.

## 8. Limitations stated in every report

1. Permission checks use ownership and mode bits together with POSIX ACLs
   when ACL state is observed; security-module policy is not evaluated.
2. Process observations cover numeric identity and executable-path context
   only; environments, command lines, memory maps, and file descriptors are
   never read.
3. Discovery runs with the privileges of the invoking user; unreadable paths
   are reported as unavailable, never bypassed.
4. Findings describe observed configuration relationships. NULQ does not
   execute discovered binaries or services and does not attempt exploitation.
5. The absence of a finding is not evidence that the system is secure.
