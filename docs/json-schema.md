# JSON contract and integration

JSON is a product interface, not a debugging convenience. The schema lives at
`schemas/nulq-report-v1.schema.json` (JSON Schema draft 2020-12) and the Go
types are importable from `pkg/api`.

## Versioning

- `schema_version` is currently `"1.1"`.
- 1.1 added the required `coverage` object (ADR 0009). Everything else is
  unchanged; consumers that ignore it keep working, but the version signals its
  presence.
- Adding optional fields does not change the version; consumers must ignore
  unknown fields.
- Removing a field, changing its type or changing semantics requires a new
  schema version and a changelog entry.
- The schema sets `additionalProperties: false` at the top level so an
  accidental field addition is caught in review; forward-compatible clients
  should still decode leniently.

## Document shape

| Field | Notes |
|---|---|
| `schema_version` | `"1.1"` |
| `tool` | name, version, commit, build date, Go version, platform |
| `host` | hostname, distribution, kernel, architecture, container, LSM list |
| `scan` | report ID, timestamps, duration, modules, roots, unprivileged, partial |
| `findings` | always an array, sorted deterministically |
| `evidence` | always an array; IDs referenced by findings |
| `observations` | present only with `--observations` (or `system info`) |
| `stats` | observation/finding/evidence counts, rule outcomes, collector status |
| `coverage` | execution vs coverage completeness, per-root examined/denied/truncated counts, excluded mounts, skipped rules, classified failed operations |
| `limitations` | report-level statements that bound interpretation |

Findings carry severity, confidence, resource, evidence IDs, explanation,
impact, remediation, limitations and references. Evidence carries observation
provenance and the observed/expected values.

### Coverage versus execution

`coverage.execution_complete` answers "did every collector and rule finish?".
`coverage.coverage_complete` answers "was the intended filesystem scope actually
inspected?". They are independent:

| `status` | Meaning |
|---|---|
| `complete` | everything ran and all scope was readable within budget |
| `partial` | ran, but some subtree was truncated or could not be traversed |
| `limited` | ran and traversed, but the environment supplied unsupported data |
| `failed` | a collector or rule failed; do not treat the result as an assessment |

A rule skipped because its data category is genuinely empty (no SUID files)
is listed in `coverage.skipped_rules` but does not downgrade the status: it is
"not applicable", not a gap.

`coverage.excluded_roots` lists mount points the collector deliberately does
not scan (pseudo filesystems such as `/proc` and `/sys`, runtime tmpfs trees,
container storage and snapshots). They are **not** traversal failures and do
not by themselves change the status. `coverage.truncated_roots` and
`permission_denied` remain the unexpected-visibility gaps.

`coverage.failed_operations` names every collector or rule that did not
complete, with a classified `class` such as `timeout`, `canceled`,
`permission_denied` or `internal`. A cancelled or timed-out rule makes
`execution_complete` false even though its status is `skipped`; a rule skipped
for genuinely missing observations stays in `skipped_rules` and does not.

Fixture scans are distinguishable by `scan.scan_roots` (for example
`/lab/fixtures`) and by their report-level limitations; the baseline scan uses
`/` with the fixture tree masked, so fixture findings can never appear as live
host facts.

## JSONL

`--format jsonl` emits one self-describing object per line:

```json
{"type":"scan","schema_version":"1.1","tool":{...},"host":{...},"scan":{...}}
{"type":"finding","id":"fnd-...","rule_id":"NULQ-FS-003",...}
{"type":"evidence","id":"ev-...","observation_id":"obs-...",...}
{"type":"observation","id":"obs-...",...}
{"type":"summary","stats":{...},"limitations":[...]}
```

Lines are independently parseable, so consumers can stream large reports.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; threshold (if any) not met |
| 1 | Runtime failure or interrupted scan (partial report may exist) |
| 2 | Usage error: unknown flag, format, module, rule or command |
| 3 | `--fail-on` threshold met |

Automation should treat `1` as "assessment incomplete" and `3` as "policy
failure with a valid report", never as interchangeable.

## Python

```python
import json
import subprocess

result = subprocess.run(
    ["nulq", "scan", "--format", "json", "--fail-on", "high"],
    capture_output=True, text=True,
)
# 0 = clean for the threshold, 3 = threshold met, 1 = scan failure
report = json.loads(result.stdout)
if report["schema_version"] != "1.1":
    raise SystemExit("unsupported report schema")

evidence = {item["id"]: item for item in report["evidence"]}
for finding in report["findings"]:
    missing = [e for e in finding["evidence"] if e not in evidence]
    assert not missing, f"{finding['id']} cites unknown evidence"
    print(finding["severity"], finding["rule_id"], finding["resource"])
```

## Shell

```bash
set -o pipefail
if nulq scan --format json --output report.json --fail-on medium; then
    echo "no finding at or above MEDIUM"
else
    status=$?
    case "$status" in
        3) echo "policy threshold met"; jq -r '.findings[] | [.severity,.rule_id,.resource] | @tsv' report.json ;;
        1) echo "assessment incomplete"; exit 1 ;;
        *) echo "invocation error ($status)"; exit 2 ;;
    esac
fi
```

## Go

```go
report, err := api.ParseReport(file)
if err != nil {
    return err
}
for _, finding := range report.Findings {
    fmt.Println(finding.Severity, finding.RuleID, finding.Resource)
}
```

## Validation

`additionalProperties: false` and explicit `required` lists make the schema
usable in CI with any draft-2020-12 validator. NULQ's own tests decode reports
and assert referential integrity and deterministic ordering; they do not assume
a network accessor for the schema.

## Stability guarantees

- Stable IDs are content-derived (`obs-…`, `ev-…`, `fnd-…`).
- Ordering is deterministic for identical state.
- Timestamps and the report ID differ between runs by design.
- Observations are opt-in for scans to keep default reports small; consumers
  that need full provenance request them explicitly.
