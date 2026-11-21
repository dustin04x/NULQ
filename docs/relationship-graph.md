# Relationship graph

> **Status: design, not implemented.** This document specifies the M5
> component. v0.1.0 reports isolated observations only. Nothing here is claimed
> as shipped behaviour.

## Why a graph

Isolated facts rarely establish a privilege boundary. The interesting
statements are relational:

- the current user can write to directory D;
- service S executes `/opt/app/run.sh` inside D;
- that script is owned by root;
- S runs with `User=root`.

Only together do these facts describe an exposure. A typed in-memory graph
makes such chains explicit, inspectable and explainable, without becoming a
generic graph database.

## Node types

| Node | Identity | Key attributes |
|---|---|---|
| User | uid | name, groups, euid |
| Group | gid | name, privileged classification |
| File | path | mode, owner, group, SUID/SGID, capabilities |
| Directory | path | mode, owner, sticky, writable_by_current_user |
| PathEntry | literal entry | index, resolved target, writable |
| Service | unit name | user, executable references |
| ScheduledTask | cron/at identity | owner, command, referenced files |
| Capability | capability name | effective/permitted/inheritable |
| Namespace | inode identifier | type |
| SecurityControl | module name | active, enforcing |

Nodes derive from observations; they are not a second collection path. A node
carries the observation IDs that justified it.

## Edge types

| Edge | Meaning | Observed or inferred |
|---|---|---|
| `member_of` | user → group | observed |
| `owns` | user/group → file/directory | observed |
| `writable_by` | directory/file → user | observed (mode bits) |
| `contains` | directory → file | observed |
| `executes` | service/task → file | observed in configuration |
| `runs_as` | service/task → user | observed in configuration |
| `has_capability` | file/process → capability | observed |
| `mounted_from` | path → mount | observed |
| `influences` | directory → file | **inferred**, confidence-scored |

Every edge has a type, source observation references, an explanation and an
explicit `observed`/`inferred` flag. Inferred edges carry confidence and must
never be presented as facts.

## Example chain

```text
(alice) --writable_by--> (/opt/app) <--contains-- (/opt/app/run.sh)
      \                                              ^
       \                                             |executes
        \                                        [unit app.service]
         \                                          |
          \--member_of--> (wheel)                   runs_as--> (root)
```

A correlation rule can walk:

1. `writable_by(dir, currentUser)` — observed.
2. `contains(dir, script)` — observed.
3. `executes(service, script)` — observed from unit configuration.
4. `runs_as(service, root)` — observed.
5. Infer `controls(user, service-execution)` with confidence derived from the
   weakest link.

## API sketch

```go
type NodeID string

type Graph interface {
    AddNode(node Node) NodeID
    AddEdge(edge Edge) error
    Nodes(kind NodeKind) []Node
    Edges(from NodeID, edgeType EdgeType) []Edge
    Path(from, to NodeID, maxDepth int) ([]Edge, bool)
}
```

The graph is immutable after construction. Correlation rules receive a
read-only view, mirroring the observation store contract.

## Invariants

- No edge without at least one observation reference.
- No inferred edge without confidence and a rationale.
- Node identity is canonical (absolute cleaned paths, numeric IDs).
- Construction is deterministic; iteration order is stable.
- Cycles are permitted (symlink-adjacent structures can form them); traversal
  must bound depth and visited sets.
- The graph is not serialised wholesale into reports. Reports include only the
  paths relevant to findings.

## Non-goals

- No graph database, query language or persistence layer.
- No network edges.
- No speculative transitive closure without an explicit correlation rule.

## M5 acceptance criteria

- Every correlated finding lists the ordered edge chain and the observations
  behind each edge.
- Removing any cited observation invalidates the finding (reproducibility).
- A chain with an unobserved link produces a low-confidence finding or none.
- Graph construction adds no repeated filesystem traversal.
