# Scenario design

## Model

A scenario is one falsifiable statement about one scan artifact. It is not a
test script: the fixture is created once at image build time, the scan is run
once per profile, and every scenario reads the same immutable report.

```text
fixture (build time) → real collector → observation → real rule → finding
                                                   ↘ scenario expectation
```

A scenario passes only when **every** declared assertion holds. A zero exit code
from NULQ, a schema-valid report, or the mere presence of a finding is never
sufficient on its own.

## Categories

| Category | Environment | What is exercised |
|---|---|---|
| `identity` | live | unprivileged execution, container context, group membership |
| `filesystem` | synthetic | world-writable, sticky, group-writable, nested directories |
| `suid-sgid` | synthetic | SUID/SGID metadata, ownership, location calibration, negatives |
| `path-hijack` | synthetic | writable, empty, relative, symlinked and missing PATH entries |
| `coverage` | live/synthetic | complete traversal versus unreadable scope, exclusions |
| `system` | live | sysctl collection, MAC observation honesty |
| `capabilities` | unsupported | planned capability parsing (M3) |
| `sudo` | unsupported | planned sudoers parsing (M3) |
| `systemd` | unsupported | planned unit parsing (M3) |
| `cron` | unsupported | planned cron parsing (M3) |
| `containers` | unsupported | planned runtime-config parsing (M4) |

`environment: unsupported` is deliberate. The fixtures exist, no rule consumes
them, and the validator reports the scenario as `UNSUPPORTED`. It is excluded
from the pass denominator. This is how the laboratory stays honest about
coverage instead of letting unimplemented checks look green.

## Manifest

`lab/scenarios/manifest.json`:

```json
{
  "schema_version": "1.0",
  "target": "Alpine Linux 3.22 (BusyBox), linux/amd64",
  "artifacts": {"baseline": "scan.json", "fixtures": "scan-fixtures.json"},
  "scenarios": [
    {
      "id": "FS-005",
      "title": "Set-owner-ID executable outside standard directories",
      "category": "suid-sgid",
      "environment": "synthetic",
      "supported": true,
      "scan": "fixtures",
      "scope": ["/lab/fixtures/"],
      "expect": {
        "findings": [{
          "rule_id": "NULQ-FS-001",
          "resource": "/lab/fixtures/suid/root-owned-tool",
          "match": "exact",
          "severity": "MEDIUM",
          "confidence": "HIGH",
          "min": 1,
          "max": 1
        }]
      }
    }
  ]
}
```

### Expectations

| Key | Semantics |
|---|---|
| `findings` | Each entry must match between `min` and `max` findings (default: exactly one). `severity`/`confidence` mismatches are reported separately and fail. |
| `absent_findings` | No matching finding may exist. Severity and confidence filters are honoured, so "no HIGH finding here" does not match the expected MEDIUM finding. |
| `observations` | At least `min` observations (default 1) of `kind`, optionally filtered by exact `resource`, `status` and `attr`/`equals`. |
| `coverage` | Exact status, `coverage_complete`, `execution_complete`, a minimum permission-denied count, and required deliberately excluded roots. |
| `allowed_findings` | Findings that are expected but deliberately not asserted (for example kernel-dependent sysctls). They are accounted for, not required. Anything neither asserted nor allowed is **unaccounted** and fails the run, even outside a scenario scope. |
| `report` | `scan.unprivileged`, required scan roots and excluded scan roots. |
| `max_severity` | No finding in the artifact may exceed this severity. |

Resource matching modes: `exact` (default), `prefix`, `glob`, `any`.

### Scope and unexpected findings

`scope` is a list of resource prefixes. Any finding inside that scope that no
positive expectation claimed is an **unexpected finding** and fails the
scenario. Scenarios without scope (baseline) skip this analysis, because a full
filesystem assessment legitimately produces findings the manifest does not
enumerate. That is also why `max_severity` is set on baseline scans where the
test asserts absence of escalation.

### Integrity checks

A scenario can pass every expectation and still describe an unreliable report.
The validator therefore fails the whole run when a scan contains duplicate
findings (same ID, or same rule/resource/title under two IDs), a finding that
cites an evidence ID not present in the report, or a finding with no evidence.
These are properties a JSON Schema cannot express.

It also performs per-scan accounting across all scenarios: every finding must
be matched by a positive expectation or by `allowed_findings`. `scope` only
localises the per-scenario unexpected check; it can no longer hide an
unaccounted finding in a scan. `expected_findings` counts assertion minima
(including duplicate inventory assertions), not distinct findings, so it is not
an "expected total" and must not be compared with `actual_findings`.

## Design rules

1. **One relationship per scenario.** A scenario that asserts SUID severity and
   PATH writability at once cannot report which one broke.
2. **Exact fixture paths.** Prefix or glob matching is used only for grouped
   absence checks.
3. **Negative controls are mandatory** for every rule touched by the lab.
4. **Severity and confidence are asserted**, not just presence.
5. **Coverage is asserted** where a fixture makes it partial.
6. **No fabricated data.** A scenario never accepts a mocked observation; it
   reads the binary's JSON.
7. **Unsupported is a status, not a failure and not a pass.** The reason names
   the milestone that will implement it.
8. **Stable IDs.** Scenario IDs are never renumbered; a retired scenario stays
   in the changelog.

## Adding a scenario

1. Add the fixture in `lab/docker/alpine/setup-fixtures.sh` with an explicit
   mode and owner, and document it in `lab/fixtures/README.md`.
2. Rebuild the image (`make lab-build`).
3. Run the scan once and inspect the JSON. Write the expectation from the
   *intended* security property, not from whatever the rule happened to emit.
4. Add the scenario to the manifest; choose `scope` narrow enough that
   unexpected findings are meaningful.
5. Run `make lab-test`; confirm the scenario passes and that a deliberate
   regression (for example changing severity) would fail it.
6. Add the scenario to the table in `lab/README.md` if it introduces a new
   category.

## Result taxonomy

| Status | Meaning |
|---|---|
| `passed` | Every assertion held, every in-scope finding was expected |
| `failed` | At least one assertion failed; checks name the exact expectation |
| `unsupported` | The check has no implementation yet; excluded from the pass rate |

Collection failures, schema violations, isolation failures and unexpected
findings are reported separately in `validation.json` and `summary.md`.
