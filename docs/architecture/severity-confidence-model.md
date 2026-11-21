# Severity and confidence model

Severity states what the observed evidence justifies; confidence states how
strong that evidence is. They are deliberately independent. A well-observed
configuration can be LOW severity, and a HIGH-severity relationship can still
carry MEDIUM confidence when one link is inferred rather than observed.

NULQ never assigns severity from how unusual a file looks. It assigns severity
from the security relationship it can demonstrate with collected observations.

## Severity levels

| Level | Meaning | Typical evidence |
|---|---|---|
| `INFO` | Inventory or environmental metadata. Useful to know; no exposure established. | A set-owner-ID bit in a standard directory, a non-executable privileged bit, kernel parameters within baseline. |
| `LOW` | A contextual weakness that requires additional, unobserved conditions to cross a boundary. | Writable PATH entry with no observed privileged consumer; unusual SUID location; sudo-group membership without the sudo policy. |
| `MEDIUM` | A meaningful misconfiguration with a credible security consequence and sufficient supporting evidence. | World-writable non-sticky directory; writable privileged executable owned by another account; SELinux permissive. |
| `HIGH` | A clearly established privilege-boundary exposure with strong evidence. | Root-owned privileged executable writable by the assessed user; root-owned privileged executable directly replaceable in a world-writable directory; membership of a group with unconditional root-equivalent authority (`docker`, `disk`). |
| `CRITICAL` | Reserved for exceptionally severe, well-supported conditions. NULQ currently assigns none. | — |

`HIGH` is not "a SUID file exists" and not "a directory is writable". It
requires an observed relationship in which the assessed user can influence
content that is executed with another account's authority, or can already
exercise that authority directly.

## Confidence levels

| Level | Meaning |
|---|---|
| `HIGH` | Every fact the conclusion depends on was observed directly; the inference is mechanical. |
| `MEDIUM` | The observed facts are reliable, but a consequence depends on an unobserved consumer, policy or environment. |
| `LOW` | Evidence is incomplete, indirect or environment-specific; the finding is a lead, not a conclusion. |

Confidence never substitutes for severity. A MEDIUM-severity finding with HIGH
confidence is not a vulnerability merely because its evidence is strong.

## Rule-by-rule contract

| Rule | Observation requirements | Severity behaviour | Explicitly not claimed |
|---|---|---|---|
| `NULQ-FS-001` | Regular file mode (execute bits), owner UID, set-user-ID/set-group-ID bits, current-user writability, execution context EUID | INFO for standard-directory inventory and inert non-executable bits; LOW for non-standard location, non-root owner, or self-owned writable file; MEDIUM when another non-root account's privileged executable is writable; HIGH only when a root-owned executable is writable by the assessed user | That the binary is exploitable, that its logic is unsafe, or that a non-standard location is itself a vulnerability |
| `NULQ-FS-002` | Directory mode, sticky bit, other-write bit, owner UID, assessed EUID, and directly contained executables with owner/SUID/SGID bits | MEDIUM for a world-writable non-sticky directory; HIGH only when a **root-owned SUID executable** is a direct child and the sticky bit does not protect it (non-sticky, or sticky directory owned by the assessed user); confidence MEDIUM because execution is not observed | That any process consumes the directory by name; that a nested file, a user-owned SUID file or an SGID file grants root; that a root-owned sticky directory is replaceable by the assessed user |
| `NULQ-FS-003` | PATH entries of the NULQ process, index, absolute/relative form, existence, resolved target mode, owner UID, current-user writability, execution EUID | LOW for empty, relative, or writable entries; no finding when the assessed user cannot write | That a privileged consumer exists, that sudo uses this PATH, or that ordering alone creates exposure; a PATH entry after trusted locations is still only LOW |
| `NULQ-ID-001` | Supplementary/primary group membership, GID, source | HIGH for groups with unconditional root-equivalent authority (`docker`, `podman` socket, `lxd`/`lxc`, `libvirt`, `disk`); MEDIUM for `input`; LOW for `wheel`/`sudo`/`admin`/`root` membership | That the sudo policy actually authorises the account, or that a group's local configuration matches the documented default |
| `NULQ-SYS-001` | Curated sysctl values with status | LOW for security-relevant deviations, INFO for defence-in-depth parameters | That a particular exploit applies to the running kernel; shared-kernel container values are host-kernel facts |
| `NULQ-SYS-002` | LSM list, AppArmor enablement, SELinux state | LOW when no MAC module enforces and every advertised module's state is known; MEDIUM when SELinux is permissive | That a module is enforcing merely because it appears in the LSM list; that one permissive module cancels another enforcing module; that an unreadable or absent state file means disabled |

## Boundary rules

1. **Inventory is not exposure.** A privileged bit, a group name or a mount
   option is inventory until an observed relationship makes it actionable.
2. **Location is not severity.** A SUID binary outside `/usr/bin` is worth
   review, not a vulnerability.
3. **Writability is not escalation.** Directory and file mode bits describe
   what the assessed user can modify. Escalation additionally requires content
   that another, more privileged context consumes or executes.
4. **Direct replaceability is exposure.** Directory write permission allows
   unlinking and renaming only entries directly inside that directory. Nested
   files are not escalated by a writable parent.
5. **Non-executable bits are inert.** Set-user-ID requires an execute bit; on a
   regular file, set-group-ID without execute means mandatory locking.
6. **Unknown is not disabled.** A missing LSM list, unreadable state file or
   absent sysctl produces no weakness claim. An advertised MAC module with no
   usable state observation suppresses the generic "no MAC enforcing" finding.
7. **Policy is not inferred.** Sudo, PAM and per-domain MAC policy are not
   evaluated in M1.5; membership rules stay LOW where authority depends on them.

## Limitations that apply to every rule

- POSIX ACLs are not evaluated; writability is derived from mode bits, owner,
  and the assessed user's supplemental groups.
- Privileged consumers (services, sudo `secure_path`, cron, systemd) are not
  enumerated until M2/M3. PATH and writable-directory findings therefore stop
  at LOW/MEDIUM unless direct replaceability or writability establishes a
  boundary from observed facts alone.
- The container shares the Docker host kernel; sysctl and LSM observations
  describe that kernel.
- Findings describe observed configuration. They are not exploitability
  verdicts, and the absence of a finding is not evidence of security.

## Change control

Severity or confidence changes require:

1. an explanation of which evidence relationship changed;
2. a positive and a negative scenario in `lab/scenarios/manifest.json` where the
   rule is supported by the laboratory;
3. a unit test asserting the boundary (for example nested SUID does not
   escalate);
4. an entry in `CHANGELOG.md`.
