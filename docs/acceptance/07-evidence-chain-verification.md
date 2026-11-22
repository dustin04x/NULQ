# Phase Seven: End-to-End Evidence Chain Verification

**Recorded:** 2026-11-22T09:46:00Z  
**Scan:** `nulq scan --format json` on Arch Linux host, 1044 findings  

## Evidence chain requirements

Every finding must cite at least one evidence item that resolves to an
observation ID. Evidence IDs are content-derived so duplicate references
collapse. Aggregation enforces referential integrity and rejects dangling
references. A finding whose evidence cannot be reproduced from the report is
a defect.

## Verification method

Ran `nulq scan --format json` and validated:
1. Every finding has non-empty `evidence[]` array
2. Every evidence ID references a valid observation
3. No dangling evidence references
4. Evidence values match observation attributes (not conclusions)
5. No synthetic/test evidence mixed into live results

## Results

| Check | Result | Detail |
|-------|--------|--------|
| All findings have evidence | Pass | 1044/1044 findings have non-empty evidence |
| No empty evidence arrays | Pass | Every `evidence[]` has at least one entry |
| Evidence references observation IDs | Pass | Each evidence entry cites observation, field, observed value |
| No dangling references | Pass | Aggregation rejects dangling references at build time |
| Evidence is observational, not conclusory | Pass | Evidence cites attribute values, not rule conclusions |
| No synthetic evidence in live scan | Pass | Lab/test observation sets never emitted by binary |

## Sample evidence chain

Finding `fnd-b1b20888e060` (NULQ-FS-002, world-writable directory):
- Evidence IDs: `ev-75d14cd79a18`, `ev-56649708bbae`, `ev-b79bc4bce29c`, ...
- Each evidence references: observation ID, attribute (`mode`, `owner_user`, `world_writable`, ...), observed value
- The value `0777` (mode) is the raw observation, not a conclusion
- The rule's conclusion ("world-writable without sticky bit") is derived from the evidence, not restated in it

## Coverage honesty

Coverage object separates `execution_complete` (true — all roots traversed)
from `coverage_complete` (false — permission denials on some roots).
Permission denials are counted per root (49 total across /, /tmp,
/var/cache/pacman/pkg, /var/log). Excluded roots (/proc, /sys, /dev,
docker overlayfs) are listed separately from traversal failures.

## No defects found

The evidence chain is complete and reproducible from the report. Every
finding's evidence traces back to observation IDs with raw attribute values.
