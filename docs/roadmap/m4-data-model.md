# M4 Data Model

**NULQ — M4 architecture & engineering blueprint**

This document specifies the M4 data model: entities, relationships, evidence, and
findings. It defines each proposed type's purpose, fields, identity strategy, provenance,
validation, unknown-value behavior, serialization, and compatibility requirements.

**Gate note:** Entity and relationship types are blocked on M3.5 acceptance. They are
specified here for design completeness but must not be implemented until M3.5 is
accepted.

## Design principles

- **Identifiers are stable:** content-derived, never time- or iteration-order-dependent.
- **Relationships are explicit:** source, target, type, evidence; never inferred edges.
- **Evidence references resolve:** every cited evidence ID must exist in the report.
- **Unknown values are preserved:** UNKNOWN is a first-class value, never collapsed to
  ALLOWED/DENIED/CONFIRMED.
- **Partial observations are representable:** status enum includes partial/unavailable/error.
- **Invalid data is rejected or explicitly reported:** validation errors are classified,
  not swallowed.
- **Existing reports remain interpretable:** schema v1.1 unchanged; no field removal or
  re-typing.

---

## 1. Entity

**Package:** `internal/core/entity` (new, M4.1, blocked on M3.5)

**Purpose:** A stable identity for a resource (file, directory, mount, process,
identity) that may be observed across multiple observation kinds.

### Type

```go
type EntityID string  // content-derived, stable across scans of identical state

type Entity struct {
    ID          EntityID    `json:"id"`
    Kind        models.Kind `json:"kind"`            // observation kind that established the entity
    Resource    string      `json:"resource"`        // canonical path or identifier
    OwnerUID    *uint32     `json:"owner_uid,omitempty"`
    OwnerGID    *uint32     `json:"owner_gid,omitempty"`
    MountPoint  string      `json:"mount_point,omitempty"`
    MountID     *int        `json:"mount_id,omitempty"`
    Attributes  map[string]string `json:"attributes,omitempty"`  // normalized, cloned
    Provenance  Provenance  `json:"provenance"`
    FirstSeen   time.Time   `json:"first_seen"`      // scan start time, not wall-clock per-observation
    LastSeen    time.Time   `json:"last_seen"`
}

type Provenance struct {
    Collector string    `json:"collector"`
    ObservationID string  `json:"observation_id"`  // observation that established this entity
}
```

### Identity strategy
- `EntityID` = `stableID("ent", kindSlug(kind), resource)` (SHA-256, first 6 hex bytes).
- Stable across scans of identical system state; changes if `resource` or `kind`
  changes (documented).
- Not stable across observation-attribute schema changes (documented limitation).

### Provenance
- `Collector` and `ObservationID` cite the observation that established the entity.
- Entities are created during normalization (post-collection, pre-rules).

### Validation
- `Resource` non-empty.
- `Kind` is a known kind.
- `OwnerUID`/`OwnerGID`/`MountID` are pointers to distinguish absent from zero.

### Unknown-value behavior
- `OwnerUID`/`OwnerGID`/`MountID` nil when not observed (absent ≠ zero ≠ unknown).
- `Attributes` may be empty; missing keys are absent, not empty.

### Serialization
- JSON via `encoding/json`; `omitempty` on optional pointers/maps so absent fields
  are omitted (stable across scans).

### Compatibility
- New type; no change to existing observation/finding contracts.
- Entities are not emitted in the default report unless `IncludeObservations`-style
  flag is added (M4.4 decision); they are internal to correlation unless exposed.

---

## 2. Relationship

**Package:** `internal/core/relationship` (new, M4.1, blocked on M3.5)

**Purpose:** An explicit, evidence-backed semantic edge between two entities.

### Type

```go
type RelationshipID string  // content-derived

type RelationshipType string

const (
    ProcessExecutes       RelationshipType = "process_executes"
    ProcessRunsAs         RelationshipType = "process_runs_as"
    PathResolvesTo        RelationshipType = "path_resolves_to"
    ObjectOwnedBy         RelationshipType = "object_owned_by"
    DirectoryContains     RelationshipType = "directory_contains"
    IdentityCanWrite      RelationshipType = "identity_can_write"
    ObjectMountedOn       RelationshipType = "object_mounted_on"
    ACLGrantsAccess       RelationshipType = "acl_grants_access"
    ObjectHasPrivilegeMeta RelationshipType = "object_has_privilege_metadata"
)

type Relationship struct {
    ID            RelationshipID     `json:"id"`
    Source        EntityID           `json:"source"`
    Target        EntityID           `json:"target"`
    Type          RelationshipType   `json:"type"`
    Evidence      []RelationshipEvidence `json:"evidence"`
    ScenarioID    string             `json:"scenario_id,omitempty"`
    EvaluationOutcome models.EvaluationOutcome `json:"evaluation_outcome"`
    Provenance    Provenance         `json:"provenance"`
}

type RelationshipEvidence struct {
    ObservationID string `json:"observation_id"`
    Field         string `json:"field,omitempty"`
    EvidenceID    string `json:"evidence_id"`   // models.EvidenceID(observation_id, field)
}

type Provenance struct {
    Collector  string    `json:"collector"`
    Evaluator  string    `json:"evaluator"`       // correlation engine or rule name
    CollectedAt time.Time `json:"collected_at"`
}
```

### Identity strategy
- `RelationshipID` = `stableID("rel", string(source), string(target), string(type),
  scenarioID)` — content-derived; duplicate edges with same endpoints/type/scenario
  collapse naturally.
- Stable across scans of identical state.

### Validation
- `Source` and `Target` non-empty and must resolve to known entities (enforced by graph
  `Add`; dangling endpoints are rejected/reported, never added).
- `Type` is a known relationship type.
- `EvaluationOutcome` is valid (confirmed/potential/insufficient/contradicted/unknown).

### Unknown-value behavior
- `EvaluationOutcome = unknown` when endpoint or evidence is missing — never inferred.
- `Evidence` may be empty when outcome is unknown/insufficient (documented).

### Serialization
- `Source`/`Target` serialized as `EntityID` strings.
- `Evidence` array always present (never null).

### Compatibility
- New type; not part of schema v1.1 report unless correlation findings are emitted
  (M4.2). Relationships are internal to the engine unless a report flag exposes them.

---

## 3. RelationshipGraph

**Package:** `internal/core/relationship` (new, M4.1)

**Purpose:** A validated, deduplicated, bounded graph of relationships.

### API

```go
type Graph struct { ... }

func NewGraph() *Graph
func (g *Graph) Add(r Relationship) error   // validates endpoints, dedups
func (g *Graph) Validate() error            // all endpoints exist, no dangling refs
func (g *Graph) Dedupe()                    // collapse duplicate edges
func (g *Graph) Cycles() [][]RelationshipID // detect cycles (bounded DFS)
func (g *Graph) Traverse(from EntityID, maxDepth int) []Relationship // bounded traversal
func (g *Graph) Edges() []Relationship      // deterministic order
```

### Validation rules
- No self-loop unless the type explicitly permits it (none of the current types do;
  a self-loop is a validation error).
- Duplicate edge (same source, target, type, scenario) → kept once; evidence unioned.
- Conflicting edges (same source/target/type, different outcome) → both retained with
  their outcomes; correlation must resolve, not silently merge.
- Cycle detection via bounded DFS (max depth configurable, default 16); cycles reported,
  traversal stops at max depth.

### Determinism
- `Edges()` returns relationships sorted by source, target, type, ID.
- Graph construction order-independent (insertion into a map + deterministic sort on
  emission).

---

## 4. Evidence (unchanged, extended semantics)

**Package:** `internal/evidence` (existing)

**Purpose:** A single observed fact supporting a finding or relationship.

### Type (existing)

```go
type Evidence struct {
    ID            string    `json:"id"`
    ObservationID string    `json:"observation_id"`
    Resource      string    `json:"resource"`
    ResourceKind  string    `json:"resource_kind,omitempty"`
    Collector     string    `json:"collector"`
    Field         string    `json:"field,omitempty"`
    ObservedValue string    `json:"observed_value"`
    ExpectedValue string    `json:"expected_value,omitempty"`
    Explanation   string    `json:"explanation"`
    CollectedAt   time.Time `json:"collected_at"`
}
```

### Identity strategy
- `EvidenceID` = `stableID("ev", observationID, field)` — content-derived; duplicate
  citations collapse.

### M4 extension
- Evidence IDs are globally consistent: the same observation+field yields the same ID
  regardless of which rule or correlation produced it (already true due to content
  derivation).
- Relationship evidence references `EvidenceID` so relationship → evidence →
  observation traceability is complete.

### Validation
- `ID` non-empty; `ObservationID` non-empty; `ObservedValue` non-empty (use
  `AbsentValue` `<not observed>` when attribute missing — already implemented).

### Serialization
- `Evidence` array always present (never null) per `Report.Normalize`.

---

## 5. Finding (unchanged)

**Package:** `internal/core/models` (existing)

**Purpose:** A rule's or correlation's evidence-backed conclusion.

### Type (existing)

```go
type Finding struct {
    ID           string      `json:"id"`
    RuleID       string      `json:"rule_id"`
    RuleVersion  string      `json:"rule_version"`
    Title        string      `json:"title"`
    Description  string      `json:"description"`
    Category     string      `json:"category"`
    Severity     Severity    `json:"severity"`
    Confidence   Confidence  `json:"confidence"`
    Resource     string      `json:"resource"`
    ResourceKind string      `json:"resource_kind"`
    Evidence     []string    `json:"evidence"`
    Explanation  string      `json:"explanation"`
    Impact       string      `json:"impact"`
    Remediation  string      `json:"remediation"`
    Limitations  []string    `json:"limitations,omitempty"`
    References   []Reference `json:"references,omitempty"`
    DetectedAt   time.Time   `json:"detected_at"`
}
```

### Identity strategy
- `ID` = `stableID("fnd", ruleID, resource, title)` — excludes `DetectedAt` and dynamic
  detail so IDs are reproducible.
- Stable across scans of identical state.

### Validation (`Validate()`)
- ID, RuleID, Title, Resource non-empty; Severity and Confidence valid; evidence
  non-empty; Explanation non-empty.

### M4 extension
- Correlated findings set `RuleID` to the correlation scenario ID (e.g., `COR-001`) with
  `RuleVersion` = correlation engine version; `RuleID` need not be one of the 8
  registered detection rules (documented exception).
- `Limitations` must state the confidence basis (weakest-link) and any UNKNOWN inputs.

### Serialization
- `DetectedAt` is wall-clock (non-deterministic). M4.4 deterministic mode normalizes it
  to the scan start time or omits it; the guarantee is documented, not default.

---

## 6. Severity and confidence (unchanged)

**Package:** `internal/core/models` (existing)

- `Severity`: INFO/LOW/MEDIUM/HIGH/CRITICAL with `Rank`/`AtLeast`.
- `Confidence`: LOW/MEDIUM/HIGH with `Rank`.
- `EvaluationOutcome`: confirmed/potential/insufficient/contradicted/unknown with `Rank`.

### M4 aggregation semantics (specified, implemented M4.2)
- Correlated finding severity = `max` of constituent severities, but **never promoted
  above the highest confirmed constituent**; low-confidence constituents do not raise
  severity.
- Correlated finding confidence = `min` of constituent confidences (weakest link); never
  increased by accumulation.
- `EvaluationConfirmed` required for HIGH/CRITICAL correlated findings; `EvaluationPotential`
  caps at MEDIUM; `EvaluationInsufficient`/`EvaluationUnknown` cap at INFO/LOW per
  documented rule.

---

## 7. Synthetic JSON example (relationship + correlated finding)

```json
{
  "schema_version": "1.1",
  "scan": {
    "report_id": "rpt-000000000000",
    "started_at": "2026-01-02T03:04:05Z",
    "finished_at": "2026-01-02T03:04:08Z",
    "duration_ms": 3000,
    "modules": ["filesystem","process"],
    "unprivileged": true,
    "partial": false
  },
  "entities": [
    {
      "id": "ent-3f2a91",
      "kind": "filesystem.file",
      "resource": "/usr/local/bin/adminhelper",
      "owner_uid": 0,
      "mount_point": "/",
      "mount_id": 1,
      "provenance": {"collector":"linux.filesystem","observation_id":"obs-3f2a91"},
      "first_seen": "2026-01-02T03:04:05Z",
      "last_seen": "2026-01-02T03:04:05Z"
    },
    {
      "id": "ent-7e4b12",
      "kind": "process.info",
      "resource": "/proc/1234",
      "owner_uid": 0,
      "provenance": {"collector":"linux.process","observation_id":"obs-7e4b12"},
      "first_seen": "2026-01-02T03:04:05Z",
      "last_seen": "2026-01-02T03:04:05Z"
    }
  ],
  "relationships": [
    {
      "id": "rel-9c1d2e",
      "source": "ent-7e4b12",
      "target": "ent-3f2a91",
      "type": "process_executes",
      "evidence": [{"observation_id":"obs-7e4b12","field":"exe_path","evidence_id":"ev-obs-7e4b12-exe_path"}],
      "scenario_id": "COR-001",
      "evaluation_outcome": "potential",
      "provenance": {"collector":"linux.process","evaluator":"correlation","collected_at":"2026-01-02T03:04:05Z"}
    }
  ],
  "findings": [
    {
      "id": "fnd-4a8b3c",
      "rule_id": "COR-001",
      "rule_version": "1.0.0",
      "title": "Replaceable root-owned SUID executable executed by privileged process",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "resource": "/usr/local/bin/adminhelper",
      "resource_kind": "file",
      "evidence": ["ev-obs-3f2a91-mode","ev-obs-3f2a91-owner_uid","ev-obs-7e4b12-process_euid"],
      "explanation": "...",
      "impact": "...",
      "remediation": "...",
      "limitations": ["Confidence is weakest-link of constituent evidence; mount nosuid state confirmed absent."],
      "detected_at": "2026-01-02T03:04:08Z"
    }
  ],
  "evidence": [
    {"id":"ev-obs-3f2a91-mode","observation_id":"obs-3f2a91","field":"mode","resource":"/usr/local/bin/adminhelper","resource_kind":"file","collector":"linux.filesystem","observed_value":"04755","explanation":"..."},
    {"id":"ev-obs-3f2a91-owner_uid","observation_id":"obs-3f2a91","field":"owner_uid","resource":"/usr/local/bin/adminhelper","resource_kind":"file","collector":"linux.filesystem","observed_value":"0","explanation":"..."},
    {"id":"ev-obs-7e4b12-process_euid","observation_id":"obs-7e4b12","field":"process_euid","resource":"/proc/1234","resource_kind":"process","collector":"linux.process","observed_value":"0","explanation":"..."}
  ]
}
```

> Note: `entities` and `relationships` are illustrative of the M4 internal model. Their
> inclusion in the emitted report is an M4.4 report-shape decision; they are not part of
> schema v1.1 and are not proposed for emission in M4 without a schema version decision.

---

## Compatibility summary

| Element | Change in M4 | Schema impact |
|---|---|---|
| Observation | none | none |
| Evidence | none | none |
| Finding | correlated findings use scenario RuleID | none (additive) |
| Entity | NEW (internal; not emitted by default) | none |
| Relationship | NEW (internal; not emitted by default) | none |
| Report | deterministic timestamps (M4.4), optional fields | none (no removal/re-type) |

No schema version bump is required in M4 unless entities/relationships are emitted in
the report (then a v1.2 with additive optional arrays would be appropriate). No field
is removed or re-typed.
