# M4 Validation Strategy

**NULQ — M4 architecture & engineering blueprint**

This document specifies how M4 workstreams are validated: unit, integration, adversarial,
property, fuzzing, race detection, cross-compile, lab, and documentation verification.

## Gate note

M3.5 was not completed. Validation stages that depend on the entity/relationship/correlation
model (M4.1, M4.2) are blocked on M3.5 acceptance. All other validation is independent.

## Validation levels

| Level | Scope | Required for |
|---|---|---|
| Unit | Single package, table-driven, deterministic | every new type/function |
| Integration | `app.Scan` on temporary fixture trees | cross-component flow |
| Adversarial | Malformed/escaped/hostile inputs | parsers, renderers, sanitizers |
| Property | Invariants across random inputs | ID stability, determinism |
| Fuzz | Random fuzz input to parsers | every parser consuming untrusted text |
| Race | `go test -race` | all packages |
| Cross-compile | `GOOS=linux GOARCH=arm64` | build target |
| Lab | Real binary in Alpine container | M4 scenarios only when implemented |
| Docs | Link resolution, ADR consistency | all docs |

## Unit test requirements

### `internal/core/entity`
- `TestEntityIDStable`: identical input → identical ID across 1000 iterations.
- `TestEntityIDChangesOnResourceChange`: different resource → different ID.
- `TestEntityValidation`: empty resource, unknown kind → error.
- `TestEntityProvenanceCitation`: provenance cites a real observation ID.
- `TestEntityAbsentVsZero`: nil vs 0 for OwnerUID/OwnerGID/MountID distinguished.
- `TestEntityAttributesClone`: mutation of input map does not affect entity.

### `internal/core/relationship`
- `TestRelationshipIDStable`: identical input → identical ID.
- `TestRelationshipDedup`: duplicate edge collapsed once, evidence unioned.
- `TestRelationshipNoSelfLoop`: source == target → validation error.
- `TestRelationshipDanglingRejected`: unknown endpoint → rejected.
- `TestRelationshipCycleBounded`: cycle detection stops at max depth.
- `TestRelationshipEdgesDeterministicOrder`: sorted output regardless of insertion order.
- `TestRelationshipUnknownOutcome`: missing evidence → `unknown`, never inferred.
- `TestRelationshipConflictingOutcomes`: both outcomes retained.

### `internal/core/relationship/graph`
- `TestGraphValidate`: all endpoints exist → pass; dangling → fail with classified error.
- `TestGraphTraverseBounded`: max depth respected.
- `TestGraphOrderIndependentConstruction`: same edges in different order → same `Edges()`.

### `internal/engine/aggregation` (M4.2 extension)
- `TestAggregationMergeDedup`: identical finding IDs merged once.
- `TestAggregationReferentialIntegrity`: dangling evidence reference → rejected.
- `TestAggregationConflictingSeverity`: max severity preserved.
- `TestAggregationConflictingConfidence`: min confidence preserved.

### `internal/platform/linux/filesystem/mounts` (M4.4)
- `TestMountContextParsing`: `/proc/self/mountinfo` parsed correctly.
- `TestBindSourceRecorded`: bind source preserved in observation.
- `TestMountFlagsEscaped`: hostile mount fields sanitized at render.

### `internal/detection/policy` (M4.5)
- `TestPolicyValidation`: invalid rule ID → rejected.
- `TestPolicySeverityOverride`: override applied at startup.
- `TestPolicyNoCodeExecution`: policy file cannot execute code (data-only).

## Integration test requirements

### `internal/app` (M4.4 deterministic mode)
- `TestDeterministicReportByteIdentical`: two scans of identical fixture tree → byte-identical
  JSON (excluding `DetectedAt`, normalized to scan start).
- `TestDeterministicReportDefaultNonDeterministic`: default mode includes wall-clock
  `DetectedAt` (documented).
- `TestScanDeterministicFlag`: `--deterministic` enables normalization.
- `TestMountContextIntegration`: bind source appears in filesystem observations.

### `internal/app` (M4.3 new rules)
- `TestRuleFiresOnFixture`: each new rule fires on its positive fixture.
- `TestRuleSilentOnNegativeControl`: each new rule silent on its negative fixture.
- `TestRuleUnavailableSkip`: rule skips when prerequisites absent, records reason.
- `TestRuleRegistration`: all rules in `All()` pass `Validate()`.

### Correlation (M4.2 — blocked on M3.5)
- `TestCorrelationFindingSeverityCap`: low-confidence constituents do not raise severity.
- `TestCorrelationConfidenceWeakestLink`: min confidence preserved.
- `TestCorrelationHighRequiresConfirmed`: HIGH requires `EvaluationConfirmed`.

## Adversarial test requirements

### Renderers/sanitizers
- `TestRendererNoTerminalEscape`: hostile path/group/attribute values cannot inject ANSI.
- `TestMarkdownSanitizer`: `<`, `>`, `&`, quotes escaped in Markdown output.
- `TestJSONSanitizer`: untrusted strings do not break JSON structure.

### Mountinfo parser
- `TestMountinfoHostileFields`: escaped spaces, newlines, tabs in mount fields do not panic
  or misparse.

### Policy parser
- `TestPolicyTraversalRejection`: `../` paths in policy references rejected.

## Property test requirements

### ID stability
- `PropertyEntityIDStableAcrossRuns`: 100 random entities → stable IDs across runs.
- `PropertyRelationshipIDStableAcrossRuns`: same.

### Determinism
- `PropertyReportDeterministicSameInput`: 20 identical scans → identical JSON bytes
  (deterministic mode).

### Graph
- `PropertyGraphDedupeConverges`: random edge insertions → deduped graph stable.
- `PropertyGraphNoSelfLoops`: no self-loop ever added.

## Fuzz requirements

- `FuzzMountinfoParse`: fuzz `/proc/*/mountinfo` text; must not panic, must return
  error on malformed input.
- `FuzzPolicyParse`: fuzz policy YAML/JSON; must not panic.
- `FuzzObservationAttributeParse`: fuzz attribute strings; must not panic.

## Race detection

- `go test -race ./...` must pass for all packages including new ones.
- Graph `Add`/`Edges` concurrent access must not race (or document single-threaded
  construction).

## Cross-compile

- `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq` must succeed.
- `go build ./...` must succeed for default platform.

## Lab validation (M4 scenarios — not yet implemented)

When M4 scenarios are implemented, each lab scenario must:
- Execute the real `nulq` binary in the pinned Alpine container.
- Validate output JSON against the published schema (`schemas/nulq-report-v1.schema.json`).
- Validate against the scenario manifest.
- Pass only when explicit expectations are met; zero exit code is not sufficient.

M4.3 rules (capabilities, seccomp, systemd, userns) are lab-testable on fixtures that
include:
- A process with CAP_DAC_OVERRIDE.
- A process with seccomp disabled running as root.
- A root-run systemd unit lacking `NoNewPrivileges`.
- `kernel.unprivileged_userns_clone = 1`.

Negative controls: equivalent fixtures without the exposure must produce no finding.

M4.1/M4.2 (entity/relationship/correlation) are **not lab-testable until M3.5 is accepted**,
because the correlation engine is not accepted infrastructure.

## Documentation verification

- All doc links resolve (`docs/architecture/severity-confidence-model.md`, etc.).
- No stale paths in M4 documents.
- Changelog entry for each new rule and each M4 stage.

## Coverage honesty (M4)

- `coverage.execution_complete` ≠ `coverage.coverage_complete`; both published.
- A completed M4 stage is not a complete M4 validation.
- Unavailable data (unreadable sysctls, missing fixtures) is an observation with status
  and error class, reflected in coverage.

## Validation order

1. Unit tests for new packages (`entity`, `relationship`, `mounts`, `policy`).
2. Integration tests for deterministic serialization and new rules.
3. Adversarial and property tests.
4. Fuzz for parsers.
5. `go vet ./...`, `go test ./...`, `go test -race ./...`.
6. Cross-compile amd64 + arm64.
7. Lab scenarios (only when M4 scenarios implemented and M3.5 accepted).

## What validation does NOT cover (limitations)

- M4 does not validate M3.5; M3.5 acceptance is a separate gate.
- M4 does not validate exploitability or CVE applicability.
- M4 does not validate runtime systemd activation state (no D-Bus).
- M4 does not validate file capabilities xattr (deferred).
- M4 does not validate seccomp BPF program semantics (only the mode flag).
