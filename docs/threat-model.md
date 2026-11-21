# Threat model

NULQ inspects systems that may be hostile. It must not become a vector for code
execution, data leakage or terminal compromise on the operator's machine.

## Assets

- The operator's workstation and terminal session.
- The integrity of the assessment (false negatives are worse than false
  positives in a security review).
- Sensitive metadata in reports: hostnames, usernames, privileged paths,
  security posture.
- The assessed system's availability (NULQ must not degrade it).

## Adversary capabilities assumed

- Control of filenames, including control characters and newlines.
- Control of file modes, ownership and symlink targets that NULQ can read.
- Malformed `/proc`-style files, mount tables and configuration.
- Very large directory trees, deep nesting, mount farms.
- A process that hangs or disappears mid-collection.

Not assumed: the ability to modify the NULQ binary or its Go runtime, or to
intercept its execution as an already-privileged observer.

## Surface analysis

| Attack | Path | Mitigation | Residual risk |
|---|---|---|---|
| Symlink redirects a read | Path traversal, PATH analysis | `WalkDir` does not follow symlinks; PATH entries resolved with `stat(2)` and the link recorded; no privileged action taken from data | TOCTOU between observation and report interpretation |
| Terminal escape injection | Filenames, group names, sysctl values | Control characters stripped before terminal/Markdown output; JSON escapes them | Unusual Unicode direction overrides are not stripped |
| Output flooding | Huge finding sets | Bounded traversal; only notable entries become observations; quiet mode; deterministic cap per root | A host with thousands of SUID binaries still produces a large report |
| Resource exhaustion | Huge trees, deep recursion | Per-root file budget; collector timeout; `WalkDir` on explicit depth-limited filesystem walk; no unbounded goroutines | Memory grows with notable observations, bounded in practice |
| Malformed configuration | Mount table, os-release | Tokens skipped on malformed lines; no panics; fuzz target for escape decoding | Future parsers need their own fuzzing |
| Command injection | Any subprocess | NULQ spawns no subprocess | None, because the capability does not exist |
| Privilege escalation by NULQ | — | Read-only code paths; no exploitation; no writes; no privilege requests | None claimed |
| Secret leakage | Observations/report | Collectors never read file contents, environments, shadow files or keys | Hostnames/usernames are included by design |
| Hanging process | Collector or rule stall | Context deadlines for collectors and rules; overall scan timeout; panic recovery | A blocking syscall may not observe cancellation promptly |
| Report tampering | Files on disk | Output files created 0600; no signing yet | Consumers must validate provenance |
| Deceptive finding | Adversarial configuration crafted to look benign | Evidence requirement, explicit limitations, confidence separation | Semantics of unusual kernels/configs may differ |

## Trust boundaries

1. **Assessed system → collectors.** Untrusted data enters through filesystem
   metadata and procfs/sysfs. Parsers are narrow and defensive.
2. **Observations → rules.** Trusted internal data, but treated as immutable and
   validated structurally.
3. **Findings → renderers.** Untrusted strings are sanitized; renderers do not
   interpret them as instructions.
4. **Report → external consumers.** Consumers must validate schema version and
   treat report contents as data, never as commands.

## Non-goals

- Detecting malicious *content* in inspected files. NULQ does not open file
  contents.
- Sandboxing the assessed system or enforcing policy.
- Defending against an attacker who already controls the operator's account or
  the NULQ binary.

## Reporting security defects

See `SECURITY.md`. A defect that causes NULQ to execute discovered content,
write to the assessed system, leak secrets or expose the operator's terminal is
a high-severity issue and should be reported privately.
