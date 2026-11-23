# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (development) | Yes, security fixes are applied |
| Older | No |

NULQ is pre-1.0; interfaces may change, but report schema version 1.1 is a
compatibility commitment described in `docs/json-schema.md`.

## Reporting a vulnerability

Do not open a public issue for a security defect in NULQ itself. Report it
privately to the maintainer listed on the repository profile, or through the
repository's private security advisory feature. Include:

- affected version/commit,
- a minimal reproducer or exact invocation,
- observed and expected behaviour,
- impact assessment (for example: does it let a crafted filesystem path inject
  terminal escapes, exhaust memory, or cause NULQ to execute something?).

You will receive an acknowledgement and a remediation plan. Coordinated
disclosure is expected; no bounty programme is currently offered.

## Security properties NULQ claims

- **Read-only assessment.** NULQ opens files read-only, never writes to the
  assessed system, never starts or stops services, never executes discovered
  binaries or scripts, and never attempts privilege escalation.
- **No network use.** The scanner makes no network connections and requires no
  database or interpreter.
- **Unprivileged operation.** Baseline discovery works as an ordinary user.
  Permission-denied paths are reported as unavailable, not bypassed.
- **Sanitized output.** Control characters from paths, group names and
  observation values are stripped before terminal and Markdown rendering, so a
  hostile filesystem cannot inject escape sequences.
- **Deterministic evidence.** Findings cite the observation ID and field that
  triggered them; evidence carries the collector name and collection time.

These are properties of the current implementation and are covered by tests
where practical. They are not a guarantee that every possible hostile
configuration is handled; see `docs/threat-model.md` for the analysed surface
and residual risks.

## Threat model summary

The assessed system is treated as potentially hostile. Primary concerns:

1. Symlink and path traversal tricking the scanner into reading or attributing
   the wrong object.
2. Malformed configuration files causing panics, unbounded memory use or
   misleading results.
3. Terminal injection through filenames and attribute values.
4. Resource exhaustion via enormous trees or hostile mount layouts.
5. Leakage of sensitive values into observations or reports.

Implemented mitigations: no symlink following during traversal, `Lstat`/`Stat`
separation for PATH analysis, bounded traversal per mount, per-rule timeouts,
panic isolation, sanitization, no collection of file contents or secrets, and
privilege checks based on effective credentials.

Global scan timeouts stop long-running scans and return a partial report with a
clear error.

## Host and laboratory safety

NULQ is developed on the owner's primary workstation. `AGENTS.md` defines the
binding host-protection policy: no privilege elevation, no package or
configuration changes, no service or network changes, no modification of
unrelated Docker resources and no global Docker cleanup. If an operation could
affect the host, it is stopped and reported rather than attempted.

All dynamic testing runs in the Docker laboratory described in
`lab/README.md`: an unprivileged user in a pinned Alpine container with all
capabilities dropped, `no-new-privileges`, a read-only root filesystem, no
network, no host namespaces and no Docker socket. The only host paths mounted
are the `nulq` binary and, where explicitly required, dedicated lab fixtures —
both read-only. Container isolation is verified per run and recorded in
`lab/results/validation.json`; it is not assumed.

Synthetic sudo, capability, systemd, cron and container-runtime fixtures exist
for planned parsers. They are reported as **unsupported** scenarios until the
corresponding rules exist, and are never presented as live observations.

## Known limitations relevant to security

- ACLs and MAC policy are not evaluated; findings use mode bits only.
- NULQ does not detect TOCTOU races between collection and a finding's use. It
  performs no privileged action based on collected data, so the practical
  impact is limited to report accuracy.
- `sudo` policy, capabilities, systemd and cron rules are implemented and
  unit-tested but lack Alpine laboratory fixtures, so they appear as
  unsupported lab scenarios. Do not treat a clean NULQ report as a complete
  privilege-escalation assessment for those domains on this target.
- The JSON schema and `pkg/api` accept unknown fields for forward
  compatibility; consumers must validate the `schema_version` they rely on.

## Hardening recommendations for deployments

- Run NULQ as the least-privileged account adequate for the assessment.
- Treat reports as sensitive: they enumerate privileged configuration, host
  identity and account membership. Output files are created with mode 0600.
- Do not feed untrusted reports into privileged automation without schema
  validation and sanitization at the boundary.
- Do not enable any future capability for executing discovered content; if
  such a feature is ever proposed, it belongs in a separate tool.
