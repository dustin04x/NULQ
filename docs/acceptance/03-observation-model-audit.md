# Phase Three: Adversarial Observation Model Audit

**Recorded:** 2026-11-22T09:42:00Z  
**Reference:** `docs/observation-model.md`, `internal/core/models/attributes.go`  

## Scope

Audit all 18 observation kinds against the documented model:
- Shape, kind vocabulary, attribute encoding, status semantics, ID derivation,
  privacy/redaction, collector-rule attribute contract.

## Findings

### Conformance (pass)

| Check | Result | Evidence |
|-------|--------|----------|
| Observation shape matches documented JSON | Pass | `internal/core/models/observation.go` produces id, kind, resource, collector, collected_at, status, attributes, note, error |
| Closed kind vocabulary (18 kinds) | Pass | `internal/core/models/kinds.go` defines all 18 Kind constants; docs/observation-model.md table matches |
| Attribute encoding conventions | Pass | `attributes.go` documents: booleans true/false, modes 4 octal digits, identifiers decimal, lists comma-separated sorted |
| Status semantics | Pass | `models.UnavailableObservation`, `models.NewObservation` with status complete/partial/unavailable/error |
| IDs content-derived, no timestamps | Pass | `models.ObservationID(kind, resource)` = `obs-<slug>-<12hex>` from SHA-256 |
| No secrets in attributes | Pass | Collectors never read /etc/shadow, process environ, credential files; attributes are mode/owner/path/mount flags only |
| Rules treat unavailable as unknown | Pass | `path_entry.go` skips `writable == "unknown"`; all rules check `ok` from `Attr()` and skip missing data |
| Collector-rule attribute contract | Pass | sshd collector writes `sshd_directive.<name>` and `sshd_directive` combined; NULQ-SYS-009 reads same format |

### No defects found

No observation model violations detected. Collectors and rules agree on attribute
names and formats. No attribute contains file contents, passwords, tokens, or
keys. IDs are stable across runs (content-derived, not time-based).

## Privacy check

Sample scan output: 1044 findings, none contain file contents, password hashes,
environment values, or private keys. Host identity (hostname, usernames) is
present as required for findings to be meaningful; reports are marked sensitive.

## Recommendation

None. The observation model is internally consistent and matches the
documentation. When new kinds are added, the existing process (docs update +
collector test + rule Required list) should be followed per AGENTS.md rule 6.
