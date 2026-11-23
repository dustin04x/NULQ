# Agent instructions for NULQ

This is the permanent engineering constitution for NULQ. It applies to every
change, human or automated. Read it, `MISSION.md` and `ROADMAP.md` before
modifying anything. `MISSION.md` changes per milestone; this file does not.

Where this file and a milestone instruction disagree about host safety, this
file wins and the conflict is reported rather than resolved silently.

## 1. Identity and objectives

NULQ is a read-only Linux privilege-boundary discovery and security assessment
framework written in Go. It answers one question precisely: **how does this
system grant authority, and what evidence supports that claim?**

It is authorised-use software: post-access assessments, hardening reviews,
CTF and laboratory environments, and automated security pipelines. It is not an
exploitation tool, a persistence tool or a remote-control service.

## 2. Non-negotiable invariants

1. **Read-only.** No code path may modify the assessed system, start or stop
   services, execute discovered binaries or scripts, or attempt exploitation.
2. **Evidence-backed findings.** Every finding cites at least one evidence item
   that resolves to an observation ID. The engine rejects findings that do not.
3. **Deterministic identifiers and ordering.** Observation, evidence and finding
   IDs derive from content, never from time or iteration order.
4. **No fabricated results.** Never claim a check ran, a test passed, or a build
   succeeded without command output proving it. Never present synthetic
   fixture data as a live observation.
5. **No silent failures.** Unreadable or unsupported data becomes an
   observation with a status and error class, and is reflected in coverage.
6. **Standard library only** unless an ADR in `docs/decisions/` justifies a
   dependency. Lab tooling that runs on the host follows the same rule.
7. **Machine output is sterile.** No ANSI, banners or log records on stdout in
   JSON, JSONL or Markdown modes.
8. **Sanitize untrusted text.** Every value originating in the assessed system
   passes through `internal/reporting` sanitizers before terminal or Markdown
   output.
9. **Coverage honesty.** A completed execution is not a complete assessment.
   `coverage.execution_complete` and `coverage.coverage_complete` are separate
   facts and both are published.

## 3. Host protection policy

NULQ is developed on the owner's primary Ryoku Linux workstation. That machine
is production infrastructure and the owner's daily environment, not a
disposable laboratory. **Preserving the host takes priority over completing any
milestone.**

Authorised on the host:

- read-only inspection of the running system;
- reading and editing files inside the NULQ repository;
- building and testing NULQ as the unprivileged owner account;
- using Docker only for the isolated laboratory described in `lab/`.

Forbidden on the host, without exception:

- `sudo`, `doas`, `su`, or any request for elevated privileges;
- installing, upgrading or removing host packages;
- modifying host configuration, ownership, permissions, ACLs or xattrs of
  existing host resources (including the repository's own tracked files'
  ownership);
- changing sysctls, kernel parameters, firewall rules, network configuration,
  bootloader configuration or kernel command lines;
- starting, stopping, restarting, enabling or disabling host services;
- creating or modifying host users, groups or credentials;
- writing to system directories or executing discovered system binaries;
- attempting privilege escalation, persistence or exploitation;
- modifying shell profiles, editor configuration or other unrelated user state;
- touching Docker resources that NULQ did not create, or running global
  cleanup (`docker system prune`, `docker volume prune`, `docker network
  prune`, `docker image prune -a`).

Anything that creates, deletes or reshapes state outside the repository
requires the owner's explicit instruction. If an operation could modify the
host, stop and explain the risk instead of proceeding.

### Laboratory Docker restrictions

The lab may use only:

- the pinned Alpine target image built from `lab/docker/alpine/Dockerfile`;
- non-root container users, dropped capabilities, `no-new-privileges`, a
  read-only root filesystem, no network and no host namespaces;
- read-only bind mounts of the `nulq` binary and dedicated lab fixtures;
- NULQ-labelled containers, networks and images that cleanup can identify.

The lab must never use `--privileged`, host PID/NET/IPC/UTS namespaces, added
capabilities, the Docker socket, or mounts of `/`, `/etc`, `/usr`, `/var`,
`/root`, `/proc`, `/sys` or the home directory.

If Docker is unavailable, report the prerequisite and stop. Never install or
reconfigure Docker.

### Separate vulnerable-target laboratory

A second, independently scoped vulnerable-target lab may exist at
`lab/vulnerable-target/` under the same security constraints as the primary
lab: non-root container user, all capabilities dropped, `no-new-privileges`,
read-only root filesystem wherever compatible, `network_mode: none`, no host
namespaces, no Docker socket, no host mounts, the `com.nulq.vulnerable-target`
label, and the dedicated Compose project name `nulq-vulntarget`. It must build
from a pinned base image digest, never `latest`. It must not modify the pinned
Alpine lab image, its compose file, or its cleanup scope.

The original `nulq-lab` remains restricted to its original pinned Alpine image
built from `lab/docker/alpine/Dockerfile`. The vulnerable-target lab is
independent: it has its own build, compose configuration, resource labels, and
cleanup. Existing cleanup scripts never remove vulnerable-target resources, and
vulnerable-target cleanup never removes original lab resources. No global
Docker pruning is performed by either lab.

Discovered target binaries are never executed. Findings are evidence-backed and
read-only only.

## 4. Architecture boundaries

```text
cmd/nulq                     entry point (signal handling + exit code only)
internal/app                 wiring: collectors + selected rules + report
internal/cli                 flags, output routing, exit codes
internal/core/models         observation/evidence/finding/report contracts
internal/core/errors         typed error classes
internal/core/interfaces     Collector, Rule, ObservationSet
internal/engine/*            registry, store, executor, aggregation
internal/platform/linux/*    collectors (system, identity, filesystem)
internal/rules/*             detection modules grouped by domain
internal/evidence            evidence builder
internal/reporting           renderers and sanitizers
internal/lab                 lab manifest, schema validator, verdict engine
pkg/api                      public report types for external consumers
schemas/                     published JSON Schema
lab/                         Docker laboratory, fixtures, scenarios, scripts
tests/integration            end-to-end fixture scenarios
docs/                        architecture, models, threat model, ADRs
```

Collectors normalise, rules interpret, renderers present. Rules never read the
filesystem, spawn processes or print. Collectors never assign severity. The
lab validates the real binary; it never reimplements detection.

## 5. Linux security research standards

- Model authority from kernel semantics: real vs effective credentials, file
  mode bits, capabilities, namespaces, mount flags and LSM policy. Do not
  substitute folklore for the documented model.
- Distinguish what the kernel enforces from what a distribution happens to
  configure.
- A check that requires data the process cannot read is reported unavailable;
  it is never approximated from adjacent data.
- Container, snapshot and pseudo-filesystem boundaries are respected. Do not
  attribute container internals to the host, and do not traverse trees that
  duplicate a whole filesystem unless explicitly asked.
- Do not infer exploitability, CVE applicability or binary behaviour from
  version strings or file presence.
- Cite the privilege model and any external authority in `docs/` or in the
  rule's `References`.

## 6. Observation-first architecture

- Collectors publish typed, immutable observations with a closed vocabulary of
  kinds and normalised attributes. Encoding conventions live in
  `internal/core/models/attributes.go`.
- One collection pass per resource class. Rules consume the shared store; a
  rule that needs new facts gets a new observation kind, not its own traversal.
- Observations carry provenance (collector name, collection time) and never
  contain secrets: no file contents, passwords, tokens or keys.
- New kinds require documentation in `docs/observation-model.md` and a
  collector test; the schema and the lab manifest are updated with them.

## 7. Detection rule requirements

A rule is acceptable only when all of the following hold:

1. Stable ID `NULQ-<AREA>-<NNN>` and semantic version in metadata.
2. Precise `Required` observation kinds; the engine skips rules whose
   prerequisites are absent and records the reason.
3. Every claim supported by evidence from the shared store.
4. Positive, negative and unavailable-data tests, including the severity
   boundary cases.
5. Explicit registration in `internal/rules/rules.go`.
6. Explanation, impact, remediation and limitations written for a reviewer who
   will not re-run the scan.
7. A changelog entry and, if conventions change, a documentation update.
8. Lab coverage: a scenario that proves the rule fires on the fixture and stays
   silent on the negative control, or an explicit statement that the rule is
   not lab-testable and why.

## 8. Evidence provenance

- Evidence identifies the observation, the field and the observed value; it
  never restates a conclusion.
- Evidence IDs are content-derived so duplicate references collapse.
- Aggregation enforces referential integrity and rejects dangling references.
- A finding whose evidence cannot be reproduced from the report is a defect,
  not a presentation issue.
- Synthetic evidence (unit-test observation sets) must never be emitted by the
  binary or mixed into lab results presented as live observation.

## 9. Severity and confidence discipline

- Severity states the significance of the observed relationship; confidence
  states how well the evidence supports it. Do not inflate either.
- Presence is not vulnerability. A SUID binary in a distribution directory is
  inventory. A writable PATH entry is LOW unless a privileged consumer is
  demonstrated.
- Only a privileged executable **directly inside** a world-writable directory is
  replaceable through that directory; nested files are not. A set-owner-ID bit
  without an execute bit is inert.
- Reserve HIGH and CRITICAL for relationships that plausibly cross into root or
  equivalent authority with the evidence at hand. Justify any escalation in the
  finding text.
- The binding definitions are in
  [`docs/architecture/severity-confidence-model.md`](docs/architecture/severity-confidence-model.md).
- Every finding states its limitations next to its claim.
- When a rule cannot decide, it reports less, not more.

## 10. Correlation requirements

Correlation is implemented in `internal/engine/correlation/engine.go`
(scenarios COR-001 through COR-005). Every emitted relationship carries
observation references; observed and inferred edges are distinguishable by
`EvaluationOutcome`; and no relationship is emitted with empty `Source` or
`Target` IDs or empty `Evidence`.

- A relationship requires a distinct Source and Target entity; self-referential
  relationships (Source == Target) are not emitted.
- A relationship requires at least one Evidence reference; relationships with
  empty Evidence are not emitted.
- `containsPath()` uses a boundary-aware prefix match so `/various` does not
  match against `/var`.
- Aggregate presence flags (e.g. COR-005) that cannot identify a specific
  Source/Target pair produce no relationships.
- Keep `docs/relationship-graph.md` and `docs/correlation-engine.md` labelled
  as design documentation describing the intended model.
- When correlation findings are consumed, every edge carries observation
  references, and any correlated finding lists its ordered chain and confidence
  propagation.

## 11. Error handling

- Wrap failures in a class from `internal/core/errors`: `permission_denied`,
  `not_found`, `unavailable`, `unsupported`, `malformed_input`, `timeout`,
  `canceled`, `resource_exhausted`, `internal`.
- Unavailability is data, not an error to swallow. A rule that lacks data is
  skipped with a reason; a collector that fails is published as failed.
- Never ignore an error from a write, close, parse or stat that affects output.
- Timeouts and cancellation propagate through contexts; a component that
  ignores cancellation may not be reported as healthy.

## 12. Testing standards

- Unit tests for models, parsers, registry, engine isolation, aggregation,
  renderers and every rule (positive, negative, unavailable).
- Integration tests drive the real pipeline (`app.Scan`) on temporary fixture
  trees; no root is required.
- Lab scenarios execute the real binary in the Alpine container and validate
  its JSON against the published schema and the scenario manifest.
- Tests never modify the host, never require network access, and clean up only
  what they created.
- Race detector clean. Deterministic ordering asserted. Fuzzing for every
  parser that consumes untrusted text.
- A scenario passes only when its explicit expectations are met. A zero exit
  code is not a pass.

## 13. Security restrictions on the tool

- No network listeners, remote control, plugin loading, database or telemetry.
- Output files are created 0600; reports are treated as sensitive.
- The tool must not read secrets to "improve" a finding. Redaction happens
  before publication.
- Untrusted paths, group names and attribute values are sanitized at render
  time; a hostile filesystem must not be able to inject terminal escapes.
- The lab's restrictions are part of the test: do not weaken container
  isolation to make a check succeed. Report the limitation instead.

## 14. Documentation standards

- Document behaviour, not aspiration. Anything not implemented is labelled
  planned or design.
- Keep `README.md` (user-facing), `MISSION.md` (current mission), `ROADMAP.md`
  (milestones), `CHANGELOG.md` (changes), `SECURITY.md` (policy) and ADRs
  (decisions) consistent with the code in the same change.
- Every new claim about coverage, severity or lab results must be reproducible
  from a documented command.
- Documentation links must resolve; stale paths are defects.

## 15. Code review expectations

A change is reviewable when:

- its diff is scoped to one logical change and contains no unrelated
  formatting churn;
- the reasoning is in comments where the code cannot express it, not narrated
  line by line;
- failure modes are explicit and tested;
- public contracts (schema, IDs, exit codes, CLI flags) are updated together
  with their documentation;
- the author can state what was verified by execution and what was not.

## 16. Definition of engineering quality

Correct Linux behaviour, honest coverage, reproducible evidence, and a
laboratory that proves the binary works on a system other than the developer's.
A smaller set of defensible checks beats a larger set of guesses. Every
limitation is written down where it applies.

## 17. Required commands before declaring work complete

```bash
gofmt -l .                 # must be empty
go vet ./...
go test ./...
go test -race ./...
make build
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/nulq
make lab-build             # when the lab or Docker files changed
make lab-test              # full isolated assessment + validation
```

For a release additionally:

```bash
make release
make verify
./bin/nulq version
./bin/nulq rules list
```

Report checks that could not run as limitations, never as passes. State
explicitly whether the host was modified and how that was verified.
