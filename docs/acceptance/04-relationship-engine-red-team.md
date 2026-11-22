# Phase Four: Relationship Engine Red-Team

**Recorded:** 2026-11-22T09:43:00Z  
**Component:** `internal/engine/correlation/engine.go`  
**Scenarios:** COR-001 through COR-005  

## Red-team findings (all fixed)

| ID | Scenario | Severity | Defect | Fix |
|----|----------|----------|--------|-----|
| R-001 | COR-001 | P1 | Mount relationships emitted with empty `Source`/`Target` IDs (`EntityID("")`) | Source = exe inode, Target = mount inode; skip if either empty |
| R-002 | COR-001 | P1 | Directory owner relationships emitted with empty Evidence ID (`EntityID(""))` | Evidence ID = directory inode; skip if empty |
| R-003 | COR-002 | P1 | Self-referential relationships (Source == Target == inode) emitted for files/dirs with mode+ACL | Scenario now returns no relationships; mode/ACL alone cannot determine distinct Source/Target |
| R-004 | COR-003 | P1 | Source and Target both set to `entityID` (`EntityID("")`), self-referential and empty | Source = file/dir inode, Target = mount inode; skip if either empty |
| R-005 | COR-004 | P1 | Evidence ID empty (`EntityID("")`) in both procByExec loops | Evidence ID = exe file inode; skip if empty |
| R-006 | COR-005 | P1 | All relationships emitted with empty Source/Target IDs and empty Evidence | Scenario now returns no relationships; aggregate flags cannot identify specific Source/Target |
| R-007 | All | P1 | `containsPath()` naive string-prefix match: `/various` matches `/var` | Boundary check: `path[len(mountPoint)] == '/'` or end-of-string |

## AGENTS.md rule 10 compliance after fixes

| Requirement | Status |
|-------------|--------|
| Distinct Source and Target; no self-referential | Pass — COR-002/COR-005 return empty; all others use non-empty inodes |
| At least one Evidence reference per relationship | Pass — all Evidence slices non-empty with valid IDs |
| `containsPath()` boundary-aware | Pass — `/various` does not match `/var` |
| Aggregate presence flags produce no relationships | Pass — COR-005 returns empty |
| Every edge carries observation references | Pass — all Evidence entries reference concrete observations |

## Scenarios that produce relationships

| Scenario | Produces relationships? | Basis |
|----------|------------------------|-------|
| COR-001 (executable replacement) | Yes | Process → exe file → mount → directory owner |
| COR-002 (file mode+ACL) | No | Cannot determine distinct Source/Target from mode/ACL alone |
| COR-003 (mount privilege metadata) | Yes | File/dir path → mount point with flags |
| COR-004 (shared exec / dir containment) | Yes | UID→UID (shared executable), file→file (same directory) |
| COR-005 (aggregate privilege flags) | No | Cannot identify specific Source/Target pair |

## Test coverage

- `tests/integration/correlation_test.go` tests COR-001 with full observation attributes (inode, uid, mount_point)
- No dedicated unit tests for COR-002/COR-005 (they return empty by design)

## Residual risk

COR-002 and COR-005 produce no relationships. This is conservative and correct:
a relationship without distinct Source/Target or without Evidence provides no
actionable information and would violate AGENTS.md rule 10. Future work could
add distinct entities (e.g., file owner UID → file inode for ACL_GRANTS_ACCESS)
but requires additional observation attributes not currently collected.
