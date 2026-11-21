# Observation model

Observations are the shared vocabulary between collection and detection. They
are designed to be reusable, deterministic and safe to publish.

## Shape

```json
{
  "id": "obs-filesystem-file-8f3a91c2b7d4",
  "kind": "filesystem.file",
  "resource": "/usr/bin/passwd",
  "collector": "linux.filesystem",
  "collected_at": "2026-11-21T01:38:16Z",
  "status": "complete",
  "attributes": {
    "mode": "4755",
    "setuid": "true",
    "owner_user": "root",
    "writable_by_current_user": "false"
  }
}
```

Fields:

| Field | Meaning |
|---|---|
| `id` | Stable content-derived identifier |
| `kind` | Closed observation vocabulary |
| `resource` | Canonical resource identifier (path, key, group) |
| `collector` | Provenance: which collector produced it |
| `collected_at` | UTC collection time |
| `status` | `complete`, `partial`, `unavailable`, `error` |
| `attributes` | Canonical string attributes |
| `note` | Optional human explanation of a non-complete status |
| `error` | Class and message when not complete |

## Kinds in v0.1.0

| Kind | Resource | Notable attributes |
|---|---|---|
| `system.info` | `host` | hostname, kernel release/version, architecture, os-release fields, container, runtime, cgroup version, LSM list |
| `system.security_control` | `lsm:<name>`, `selinux`, `apparmor` | active, detail, value, source |
| `system.sysctl` | kernel parameter key | value, source |
| `identity.execution_context` | `process:<pid>` | uid/euid/gid/egid, username, groups, umask, namespace identifiers |
| `identity.group_membership` | `group:<name>` | group name/ID, source (primary/supplementary), username |
| `filesystem.file` | absolute path | mode, symbolic mode, setuid, setgid, owner, group, size, writable_by_current_user |
| `filesystem.directory` | absolute path | mode, sticky, world_writable, group_writable, owner, group, writable_by_current_user |
| `filesystem.path_entry` | literal entry (or placeholder for empty) | path index, entry, exists, is_directory, symlink, symlink target, mode, owner, writable_by_current_user |
| `filesystem.mount` | mount point | device, fstype, options, read_only |
| `filesystem.scan` | root path (`mounts` for the mount table) | files_visited, dirs_visited, scan_errors, truncated |

Only **notable** files and directories are published: set-owner-ID regular
files and world-writable directories. Emitting every file would inflate memory
and reports without adding findings; the traversal still counts everything it
visits.

## Attribute encoding

Attributes are strings, deliberately:

- booleans: `true` / `false`
- modes: four octal digits (`4755`)
- identifiers: unsigned decimal
- lists: comma-separated, sorted when order is meaningless

This keeps evidence values directly comparable and stable across platforms,
and avoids `any`-typed payloads leaking untyped data into reports.

## Status semantics

- `complete`: the resource was fully observed.
- `partial`: usable but incomplete (for example, truncated traversal, missing
  umask).
- `unavailable`: could not be observed at all (permission denied, absent knob,
  unsupported kernel).
- `error`: unexpected internal failure.

Rules must treat `unavailable` as **unknown**, never as secure or insecure.

## Identity

IDs are `obs-<kind-slug>-<12 hex>` derived from SHA-256 over kind and resource.
They exclude timestamps and collector names, so the same state yields the same
IDs and reports can be diffed across runs.

## Immutability and sharing

The store copies attributes, deduplicates by ID (preferring `complete` over
`partial` over `unavailable` over `error`), and sorts by kind/resource/ID. All
rules read the same immutable snapshot, which eliminates a class of concurrency
bugs and prevents rules from accidentally influencing each other.

## Privacy and redaction

Observation attributes never include file contents, password hashes,
environment variable values, tokens or private keys. Collectors must not read
`/etc/shadow`, process environments or credential files. Host identity
(hostname, usernames) is included because findings are meaningless without it;
reports should be handled as sensitive.

## Adding a kind

1. Add the constant and document its attributes here and in the JSON schema.
2. Emit it from exactly one collector.
3. Decide which rules require it and update their `Required` lists.
4. Add store/coverage handling if it affects the `partial` computation.
5. Add tests for encoding and for the unavailable case.
