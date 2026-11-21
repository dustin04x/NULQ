# Correlation engine

> **Status: design, not implemented.** M5 work. v0.1.0 has no correlation
> engine. The current rules perform only local cross-references (for example,
> a world-writable directory that is also a PATH entry).

## Role

Detection rules evaluate one set of observations and emit findings. The
correlation engine evaluates *relationships between findings and graph edges*
to explain multi-step privilege exposure that no single observation proves.

Correlation is deliberate and rule-driven. The engine never invents transitive
chains by scanning the graph for "anything reachable".

## Correlation rule contract (proposed)

```go
type CorrelationRule interface {
    Metadata() CorrelationMetadata
    Evaluate(ctx context.Context, graph GraphView, findings []models.Finding) ([]models.Finding, []models.Evidence, error)
}
```

Metadata includes ID, version, description, required node/edge types, maximum
depth and default confidence. Correlation rules produce findings of their own
with a distinct rule ID (for example `NULQ-COR-001`), referencing the evidence
of every link in the chain.

## Confidence propagation

Confidence is the weakest-link rule, adjusted for inference:

| Link | Confidence contribution |
|---|---|
| Observed ownership, mode, membership | HIGH |
| Configuration reference (unit `ExecStart=`) | HIGH |
| Interpreted reachability through an intermediate directory | MEDIUM |
| Assumed consumer behaviour not observed | LOW |

A chain is only HIGH if every link is observed. Any inferred link caps the
result at MEDIUM; speculative links cap at LOW. Severity is assigned by the
correlation rule, not by multiplying link severities.

## Explainability

Every correlated finding must include:

- an ordered chain (`user → directory → script → service → root`);
- the observation ID for each link;
- which links are observed and which are inferred;
- the exact assumption that made the chain valid;
- what would invalidate it (for example: the unit is not enabled, the script is
  not executed, `nosuid` applies);
- remediation that breaks the chain at the cheapest point.

## Example: writable execution dependency

Inputs:

- `filesystem.directory` for `/opt/app` with `writable_by_current_user=true`;
- `filesystem.file` for `/opt/app/run.sh`, owner root;
- a systemd unit parsed in M3 with `ExecStart=/opt/app/run.sh` and `User=root`.

Output:

```text
NULQ-COR-001  User-writable execution dependency of a root service
Resource:      app.service
Severity:      HIGH
Confidence:    HIGH (all links observed)
Chain:
  alice writes to /opt/app            [obs-...]
  app.service executes run.sh there   [obs-...]
  run.sh is owned by root             [obs-...]
  app.service runs as root            [obs-...]
```

No claim is made that the service is currently running or that the attack has
been performed. Both are recorded as limitations.

## Deduplication with local rules

A local rule may already report the writable directory. Correlation findings
are additive, not duplicates: they reference the local finding's evidence and
state the additional relationship. Aggregation deduplicates only identical
finding IDs, which differ by rule ID.

## False-positive controls

- Require every link; a missing observation produces no correlation.
- Respect `nosuid`, `noexec` and read-only mount observations.
- Do not assume a service is enabled or running unless observed (M3 may record
  enablement; running state requires process evidence).
- Do not treat group-writable paths as user-writable unless the user is in the
  group in the observed credential set.
- Cap chain depth (default 4) and the number of findings per rule.

## Reproducibility requirement

Given the same observation set, a correlation finding must be regenerated
identically. Tests will persist an observation fixture and assert the exact
chain, confidence and evidence references. Any correlation that cannot be
reconstructed from its cited evidence is a defect.
