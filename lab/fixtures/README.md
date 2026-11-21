# Laboratory fixtures

All fixtures are created inside the Alpine image at build time by
`lab/docker/alpine/setup-fixtures.sh`, as root, with explicit ownership and
mode bits. They never exist on the Docker host and NULQ never executes them.

Two kinds of fixture are distinguished:

- **Observed fixtures** — real metadata read by the existing collectors and
  judged by existing rules. These back supported scenarios.
- **Planned fixtures** — plain configuration files for parsers that do not exist
  yet (M3/M4). They back `unsupported` scenarios and must never be described as
  tested behaviour.

## Observed fixtures

| Path | Mode / owner | Expected outcome |
|---|---|---|
| `/lab/fixtures/fs/world-writable` | `0777 root:root` | `NULQ-FS-002` MEDIUM / MEDIUM |
| `/lab/fixtures/fs/world-writable-sticky` | `1777 root:root` | no finding (sticky bit protects deletion) |
| `/lab/fixtures/fs/group-writable` | `0770 root:wheel` | no finding (not world-writable) |
| `/lab/fixtures/fs/nested/deep/world-writable` | `0777 root:root` | `NULQ-FS-002` MEDIUM, attributed to the inner path |
| `/lab/fixtures/fs/ww-with-suid` | `0777 root:root` | `NULQ-FS-002` HIGH: the privileged executable is a **direct child** and replaceable |
| `/lab/fixtures/fs/ww-with-suid/tool` | `4755 root:root` | `NULQ-FS-001` LOW (non-standard location, not writable) |
| `/lab/fixtures/fs/ww-nested-suid` | `0777 root:root` | `NULQ-FS-002` MEDIUM: the executable is inside a root-owned subdirectory |
| `/lab/fixtures/fs/ww-nested-suid/inner/tool` | `4755 root:root` | `NULQ-FS-001` LOW (inventory location) |
| `/lab/fixtures/fs/ww-with-user-suid` | `0777 root:root` | `NULQ-FS-002` MEDIUM: the SUID child is owned by uid 10001, so no root authority |
| `/lab/fixtures/fs/ww-with-user-suid/tool` | `4755 10001:10001` | `NULQ-FS-001` LOW (self-owned and writable) |
| `/lab/fixtures/fs/sticky-owned` | `1777 10001:10001` | `NULQ-FS-002` HIGH: the assessed owner can remove the root SUID child despite the sticky bit |
| `/lab/fixtures/fs/sticky-owned/tool` | `4755 root:root` | `NULQ-FS-001` LOW |
| `/lab/fixtures/fs/clean/plain.txt` | `0644 root:root` | negative control, no finding |
| `/lab/fixtures/suid/root-owned-tool` | `4755 root:root` | `NULQ-FS-001` LOW, never HIGH on presence alone |
| `/lab/fixtures/suid/sgid-tool` | `2755 root:wheel` | `NULQ-FS-001` LOW |
| `/lab/fixtures/suid/user-owned-tool` | `4755 10001:10001` | `NULQ-FS-001` LOW: self-owned and writable, no user boundary |
| `/lab/fixtures/suid/inert-suid` | `4644 root:root` | `NULQ-FS-001` INFO: no execute bit, the kernel ignores the bit |
| `/lab/fixtures/suid/plain-tool` | `0755 root:root` | negative control, no SUID finding |
| `/usr/lib/lab/standard-suid` | `4755 root:root` | `NULQ-FS-001` INFO (distribution-style inventory) |
| `/lab/fixtures/path/writable` | `0777 root:root` | `NULQ-FS-003` LOW (no privileged consumer observed); `NULQ-FS-002` MEDIUM |
| `/lab/fixtures/path/late-writable` | `0777 root:root` | same as above even though it appears after `/usr/bin` |
| `/lab/fixtures/path/other-owned` | `0755 10002:10002` | no `NULQ-FS-003` finding: uid 10001 cannot write |
| `/lab/fixtures/path/safe` | `0755 root:root` | negative control |
| `/lab/fixtures/path/user-owned` | `0755 10001:10001` | `NULQ-FS-003` LOW (normal user-managed directory) |
| `/lab/fixtures/path/missing` | absent | `path_exists=false`, no writability finding |
| `/lab/fixtures/links/path-link` | symlink → `path/safe` | judged by target; no finding |
| `/lab/fixtures/links/safe-link` | symlink → `fs/clean/plain.txt` | benign symlink |
| `/lab/fixtures/permissions/denied` | `0700 root:root` | unreadable by uid 10001 → partial coverage, permission denied counted |

SUID/SGID fixtures are ELF copies of `/bin/busybox`, so the metadata is
realistic. The kernel would honour the executable bits if the files were run;
NULQ never executes them and reads `stat` metadata only.

A writable PATH entry is deliberately **not** HIGH. NULQ does not observe a
privileged consumer of the container PATH, so the strongest supportable claim
is a contextual LOW. `FS-011`, `FS-017` and `FS-018` assert that boundary.

A world-writable directory is not automatically HIGH either. `FS-021` keeps a
user-owned SUID child at MEDIUM, and `FS-019` keeps a nested root SUID child at
MEDIUM. `FS-022` proves that a sticky bit protects entries only when the
directory is owned by someone other than the assessed user.

## Planned fixtures (unsupported until M3/M4)

| Path | Represents | Milestone |
|---|---|---|
| `/lab/fixtures/capabilities/example.bin` + `capability-set.txt` | file capability metadata | M3 |
| `/lab/fixtures/sudo/sudoers.d/{10-nopasswd,20-malformed,30-safe}` | sudo policy, including a malformed line | M3 |
| `/lab/fixtures/systemd/lab.service`, `lab.timer` | `User=root` unit with a writable executable dependency | M3 |
| `/lab/fixtures/cron/root` | root cron entry referencing a writable payload | M3 |
| `/lab/fixtures/containers/privileged.json` | privileged runtime configuration | M4 |
| `/lab/fixtures/path/writable/payload` | referenced executable for unit/cron fixtures | M3 |

No rule reads these files. Their scenarios are reported as `unsupported` by
`lab/scenarios/manifest.json`; they are never counted as passes.

## Rules for new fixtures

1. Explicit mode and owner; never rely on umask.
2. No secrets, credentials or real host data.
3. No fixture may modify the container at scan time; NULQ is read-only.
4. Prefer real ELF binaries over scripts for SUID metadata.
5. Add a negative control for every positive fixture.
6. Document the expected rule, severity and confidence here and in the manifest.
