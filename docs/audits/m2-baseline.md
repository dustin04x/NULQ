# M2 baseline

## Foundation
- M1.5 accepted (`docs/audits/m1.5-final-acceptance.md`): 32/32 supported lab scenarios, 5 unsupported, 0 unaccounted, schema 5/5, isolation 9/9, cleanup verified.
- Branch `master`, no commits, repository state remains uncommitted.

## Starting implementation points
- Observation model: closed `models.Kind` set in `internal/core/models/observation.go`; kind enum mirrored in `schemas/nulq-report-v1.schema.json`.
- Filesystem collector: single bounded traversal in `internal/platform/linux/filesystem/collector.go`; mount parsing from `/proc/self/mounts` in `mounts.go` (procfs format, no mount IDs/roots/superblock options); mode-bit `Credentials.CanWrite` in `perms.go`.
- Process data: only execution context (`identity.execution_context`) collected; no process enumeration.
- Rules: `NULQ-FS-001/002/003`, `NULQ-ID-001`, `NULQ-SYS-001/002`.
- App wiring: system, identity and conditional filesystem collectors in `internal/app/app.go`.
- Lab: Alpine image with synthetic fixtures, 37 scenarios, per-scan accounting and `allowed_findings` in `internal/lab/validate.go`.

## M2 design choices
- Add `process.info` kind and `linux.process` collector under `/proc`, reading only pid/ppid/comm, numeric uid/gid/euid/egid/supplementary groups, starttime identity and executable symlink/stat/parent context. Never read environ/cmdline/mem/maps/fd.
- Replace mount table parsing with `/proc/self/mountinfo` parsing that preserves mount ID, parent ID, major/minor, root, mount point, per-mount options, optional fields and superblock options; resolve paths by longest mount-point boundary, never naive prefix.
- Add `internal/platform/linux/acl` for POSIX ACL xattr parsing (`system.posix_acl_access`/`system.posix_acl_default`, version 2) and effective permission evaluation returning ALLOWED/DENIED/UNKNOWN. No external tools; unreadable/malformed ACLs remain UNKNOWN.
- Attach mount context and normalized ACL/effective-permission attributes to filesystem and process observations so rules can reason without re-scanning.
- Extend existing rules and add focused mount/writable-parent relationship rules instead of a parallel scanner or M5 graph engine.
- Preserve M1.5 guarantees, existing scenarios and validator semantics; new scenarios must be positive/negative, evidence-backed and accounted.

## Risks to control
- `/proc` races and PID reuse: use starttime identity before/after collection and discard attributes on mismatch.
- ACL absence vs unreadable: ENODATA means none; EACCES/EPERM/ENOTSUP/malformed mean not safely knowable.
- `nosuid`/`noexec` semantics: flags constrain execution behavior, not universal safety; claims must state what was and was not observed.
- Writable parent vs running process: replacing a path does not modify an already loaded image; findings must describe future-execution/restart dependency explicitly.
