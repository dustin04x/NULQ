# 0007 — Per-filesystem budgets and default exclusions

- Status: accepted
- Date: 2026-11-21

## Context

An early implementation used one global file budget and scanned every mount
point. Real-host validation exposed three defects:

1. `/` consumed the global budget, after which every remaining mount was
   reported "truncated" with zero coverage.
2. Btrfs snapshot subvolumes (`/.snapshots`) duplicated the entire root tree,
   producing 81 MEDIUM findings for copies of `/usr/bin` and inflating the
   report.
3. Non-directory bind mounts (a swapfile) produced meaningless truncated scan
   summaries.

The resulting report was technically honest about truncation but practically
misleading, and the severity distribution was dominated by duplicate snapshot
content.

## Decision

- Apply the entry budget **per filesystem root**, not globally. A large root
  cannot starve other mounts; each root reports its own coverage.
- Default budget: 1,000,000 entries per root, configurable with `--max-files`.
- Exclude by default: pseudo filesystems, kernel virtual paths, container
  storage (`/var/lib/docker`, `/var/lib/containers`, `/var/lib/lxc`,
  `/var/lib/machines`, snap mounts) and snapshot/backup trees (`/.snapshots`,
  `/snapshots`, `/.btrfs/snapshots`).
- Skip non-directory scan roots while still publishing mount observations for
  them.
- Record unreadable-entry counts per root; surface the total in report
  limitations instead of flipping `partial` for routine permission denials.
- `partial` means coverage was truncated, a collector failed, or a rule failed.

## Consequences

Positive:

- Every mount is assessed up to its own bound.
- Reports describe the live host, not repeated snapshot copies.
- Operators can deliberately assess excluded trees with `--root` and understand
  the trade-off.
- Permission-denied subtrees are counted and disclosed without making every
  unprivileged report "partial".

Negative:

- Worst-case work scales with the number of mounts, bounded by the collector
  timeout.
- Excluded trees are a documented blind spot; snapshot contents may differ from
  the live system.
- Per-root budgets are not a global time guarantee; the overall scan timeout is.

## Alternatives considered

1. **Order mounts by importance and keep one global budget.** Requires an
   arbitrary ranking and still starves the tail.
2. **Scan every mount with no budget.** Unbounded on adversarial filesystems.
3. **Skip all read-only mounts.** Would miss genuinely privileged content in
   immutable images; snapshot exclusion is narrower and evidence-based.
4. **Deduplicate findings by inode/device.** Snapshots are separate subvolumes
   with distinct inodes, so deduplication would not solve the duplication.
