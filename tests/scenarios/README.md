# Assessment scenarios

Named, reproducible scenarios implemented in `tests/integration`. Each builds
its own fixture tree at test time; no root, no committed binaries and no
dependency on the host's installed packages.

| Scenario | Test | Purpose |
|---|---|---|
| S1 Privileged locations | `TestScenarioPrivilegedLocations` | A set-owner-ID executable and a world-writable directory produce exactly one finding each, both evidence-backed |
| S2 Safe symlink PATH | `TestScenarioSafeSymlinkPath` | A `/bin`-style symlink to a non-writable directory produces no FS-003 finding (regression) |
| S3 Truncated coverage | `TestScenarioTruncatedCoverage` | Budget exhaustion sets `scan.partial` and adds a truncation limitation |
| S4 API round trip | `TestScenarioAPICompatibility` | Emitted JSON decodes through `pkg/api` with dangling-evidence detection |
| S5 Deterministic ordering | `TestScenarioDeterministicOrdering` | Two scans of unchanged state yield identical finding order |
| S6 Unknown module | `TestScenarioUnknownModuleFailsLoudly` | Invalid selection is an error, not an empty scan |
| S7 Model invariants | `TestScenarioModelInvariants` | Schema version, tool identity, timestamps and limitations are coherent |

## Adding a scenario

1. Create the smallest fixture tree that expresses the relationship.
2. Run the real pipeline through `app.Scan` (not a synthetic rule call).
3. Assert the rule ID and severity, not just "some finding exists".
4. Assert evidence integrity for every finding.
5. Add a row to this table.

Scenarios that require root-owned fixtures cannot be reproduced unprivileged
and are covered by synthetic observation sets in the rule tests. A privileged,
opt-in scenario harness is tracked in the roadmap (M7).
