# NULQ LAB

An automated, disposable Linux security-assessment laboratory. It runs the
**real** `nulq` binary as an unprivileged user inside a minimal Alpine
container, validates the JSON it emits against the published schema, checks
scenario expectations and writes reproducible reports.

It is not a scanner reimplementation and it is not a VM tutorial. With Docker
running, one command does everything:

```bash
make lab-test
```

No root, no ISO, no second distribution, no manual container configuration.

## What it proves

| Property | How it is verified |
|---|---|
| The real binary works on another Linux system | `bin/nulq` is built and bind-mounted read-only into the container |
| It works without privileges | container uid 10001; `scan.unprivileged` asserted |
| Output conforms to the published contract | every report validated against `schemas/nulq-report-v1.schema.json` |
| Findings fire on real metadata | SUID/SGID, world-writable, PATH and group fixtures observed through the real collectors |
| Negative cases stay silent | sticky/group-writable directories, plain binaries, safe symlinks, missing PATH entries |
| Coverage is honest | an unreadable subtree produces `coverage.status: partial` and a denial count |
| The container is actually isolated | in-container probe: read-only root, zero capabilities, `no-new-privileges`, loopback only, no Docker socket |
| Unsupported checks are not faked | 5 scenarios are reported as `UNSUPPORTED` because their rules do not exist yet |

## Quick start

```bash
make lab-build     # build bin/nulq + the pinned Alpine image
make lab-test      # run scans, validate, write reports (no interaction)
make lab-status    # inspect NULQ resources only
make lab-cleanup   # remove NULQ containers and image; global prune is never run
```

Optional manual inspection:

```bash
make lab-up
docker compose -p nulq-lab exec lab-target sh
make lab-logs
make lab-down
```

`make lab-reset` rebuilds the image without cache from the Dockerfile and
fixtures, discarding any drift.

Docker is a prerequisite. If it is missing or its daemon is unreachable, the
scripts stop and say so; they never install or reconfigure Docker.

### Last verified

Alpine 3.22.8 (base digest `sha256:49340b34…`), NULQ `0.1.0-dev`:

- 32/32 supported scenarios passed; 5 unsupported (capabilities, sudo, systemd,
  cron, container runtime) reported as unsupported, not as passes;
- 5/5 reports valid against the published schema, cross-checked with Python
  `jsonschema`;
- 9/9 isolation checks passed (uid 10001, read-only root, zero capabilities,
  `no-new-privileges`, no routable network, no Docker socket, binary executes,
  `/tmp` writable but non-executable);
- 0 missing, 0 unexpected, 0 unaccounted, 0 duplicate findings, 0 dangling
  evidence, 0 findings without evidence, 0 severity/confidence mismatches;
- built image 27,660,248 bytes (≈26.4 MiB), including real ELF SUID fixtures,
  owner/sticky variants and the inert non-executable SUID negative control;
- the manifest contains 37 scenarios: 32 supported and 5 explicitly
  unsupported.

## Layout

```text
lab/
├── compose.yaml                 hardened services (no network, no privileges)
├── .env.example                 optional overrides
├── docker/alpine/
│   ├── Dockerfile               pinned alpine:3.22 image
│   ├── setup-fixtures.sh        deterministic fixture construction (build time)
│   └── probe.sh                 in-container isolation proof
├── fixtures/                    documentation of every fixture
├── scenarios/manifest.json      scenario contract and expectations
├── scripts/                     lab-build/up/status/test/logs/down/reset/cleanup
├── verify/                      validation CLI (Go, no dependencies)
└── results/                     generated artifacts (git-ignored)
```

## What is live and what is synthetic

Three different things appear in a run, and the reports keep them separate:

1. **Live container observations** — the Alpine userland, kernel parameters,
   mounts, credentials and group membership actually present in the container.
   `scan.json` is a baseline scan with `/lab/fixtures` masked by an empty
   tmpfs, so fixture findings can never be mistaken for live facts.
2. **Synthetic fixtures observed live** — files and directories created at
   image build time with real ownership and mode bits (SUID binaries are real
   ELF copies of BusyBox). NULQ observes their metadata through its normal
   collectors; this is not a mocked observation, but it is also not a
   distribution's package state. `scan-fixtures.json` and `scan-path.json`
   cover these.
3. **Unsupported checks** — sudo, capabilities, systemd, cron and container
   runtime fixtures exist as plain files for planned parsers (M3/M4). No rule
   reads them, so their scenarios are reported as `UNSUPPORTED`, never as
   passed.

## Security model

Every service runs with:

- `user: "10001:10001"` (non-root, no login shell, no home);
- `cap_drop: [ALL]` with `no-new-privileges`;
- `read_only: true` root filesystem;
- a 1 MiB `noexec,nosuid,nodev` tmpfs at `/tmp`;
- `network_mode: none` (loopback only);
- no host PID/NET/IPC/UTS namespaces;
- no Docker socket, no privileged mode;
- exactly one bind mount: `bin/nulq`, read-only.

`lab/scripts/lib.sh` refuses to run as root and rejects a Compose file that
contains privileged mode, host namespaces, added capabilities or sensitive host
mounts. The probe verifies the properties from inside the container on every
run; see [docs/testing/docker-security-model.md](../docs/testing/docker-security-model.md).

## Reports

`make lab-test` writes to `lab/results/`:

| File | Content |
|---|---|
| `scan.json` | baseline assessment of the live Alpine userland |
| `scan-fixtures.json` | fixture-root assessment (SUID, permissions, coverage) |
| `scan-path.json` | hostile PATH assessment (writable, empty, symlink, missing) |
| `scan-identity.json` | wheel membership assessment |
| `scan-discovery.json` | auto-discovered mount scan (excluded roots vs failures) |
| `isolation.json` | container probe output |
| `image.json` | image, digest, base image and NULQ version |
| `validation.json` | machine-readable verdict: scenarios, findings, coverage, isolation |
| `summary.md` | human-readable report |

`validation.json` separates passed, failed and unsupported scenarios, expected
versus actual findings, missing, unexpected and **unaccounted** findings,
allowed-but-unasserted findings, severity and confidence mismatches, duplicate
findings, dangling evidence, findings without any evidence, per-scan coverage
and collection errors. Every finding in every scan must be asserted or
explicitly allowed; scope no longer hides unclaimed findings. A successful NULQ
exit code alone never counts as a pass.

## Cleanup guarantees

`make lab-down` removes only the `nulq-lab` Compose project. `make lab-cleanup`
additionally removes leftover containers that carry both the project and
`com.nulq.lab` labels, and the image only when it carries `com.nulq.lab=true`.
It never runs `docker system prune`, `docker volume prune`, `docker network
prune` or `docker image prune -a`. Results directories are kept.

## Known limitations

- Alpine/BusyBox is not systemd, PAM, SELinux or a distribution package set;
  those checks are synthetic or unsupported.
- The container shares the Docker host kernel, so sysctl observations describe
  that kernel.
- `--root /lab/fixtures` narrows discovery; those reports are fixture
  assessments, not host assessments.
- Docker Desktop on macOS/Windows runs a Linux VM; the image is linux/amd64 or
  arm64 depending on the host, and the manifest targets amd64. The validator
  does not depend on architecture, but the recorded image digest does.
- Cleanup is label-scoped, not name-scoped: renaming resources by hand can
  leave them behind.
- The baseline scan reports `coverage.status: partial` by design: Alpine's
  `/root` is `0700 root:root`, so an unprivileged scan cannot enter it. The
  denial is counted rather than hidden; claiming complete coverage would be
  false.
