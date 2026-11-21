# Docker laboratory security model

## Assets to protect

1. The owner's primary Ryoku workstation (files, configuration, services,
   Docker state).
2. The integrity of the assessment result: a run must not be able to "succeed"
   by weakening its own sandbox.
3. The repository: no root-owned artifacts, no generated binaries committed.

## Threats considered

| Threat | Control |
|---|---|
| Test code obtains root on the host | container is non-root with all capabilities dropped; no host namespaces; no privileged mode |
| Test code modifies the host filesystem | read-only rootfs; only `bin/nulq` is bind-mounted, read-only; fixtures live inside the image |
| Test code reaches the Docker daemon | no socket mount; probe asserts `/var/run/docker.sock` is absent |
| Test code talks to the network | `network_mode: none`; probe asserts loopback only |
| A malicious fixture influences the host | fixtures are synthetic files inside the image; NULQ never executes them |
| Privilege escalation through SUID fixtures | SUID bits are metadata only; `no-new-privileges`; capabilities dropped; none of the fixtures is executed |
| Compose drift weakens isolation | `lab/scripts/lib.sh` rejects privileged mode, host namespaces, added capabilities, Docker socket and sensitive host mounts before any command runs |
| Cleanup destroys unrelated resources | cleanup is scoped by Compose project and `com.nulq.lab` labels; no global prune is ever invoked |
| Results leak to an unintended place | captured on the host as regular files; no writable volume is mounted into the container |

## Controls in detail

### Identity

`user: "10001:10001"`. The account is created at image build with no home and a
nologin shell. `wheel` is not a member of the image account; the identity
profile grants gid 10 through `group_add` so the membership is a runtime
property of that one scan, not a baked-in privilege.

### Capabilities

`cap_drop: [ALL]`. The probe reads `CapEff` from `/proc/self/status` and asserts
it is all zeros. With a non-root user and all capabilities dropped, both the
effective and permitted sets are empty.

### Filesystem

`read_only: true`, plus a 1 MiB tmpfs at `/tmp` mounted
`rw,noexec,nosuid,nodev`. The probe attempts a write to `/lab` (must fail) and
executes a script in `/tmp` (must fail). Results are written by the **host**
through stdout redirection, so NULQ needs no writable path.

### Network and namespaces

`network_mode: none`, no `pid`, `ipc`, `uts` or `userns_mode` settings. The
probe asserts `/sys/class/net` contains only `lo`. Host namespace sharing would
be visible to the guard script and is rejected.

### Mounts

Exactly one bind mount, the binary, read-only, with
`bind.create_host_path: false` so a missing build fails instead of creating a
directory. No `/`, `/etc`, `/usr`, `/var`, `/root`, `/proc`, `/sys` or home
mounts. The guard rejects those targets.

### Resource limits

The tmpfs is size-limited so a runaway writer cannot exhaust host memory. The
lab runs one-shot containers with `--rm`; `lab-up` starts a single `sleep`
container for inspection.

## Verification per run

`lab-probe` runs on every `make lab-test` and its output is stored as
`lab/results/isolation.json`. `internal/lab` turns it into assertions:

- non-root uid;
- read-only root filesystem;
- empty effective capability set;
- `no-new-privileges` set;
- only loopback network;
- Docker socket absent;
- mounted binary executes;
- `/tmp` writable and non-executable.

Any false value fails the whole laboratory run and adds a limitation to
`validation.json`. The claim "the lab is isolated" is therefore evidence, not
configuration.

## What this model does not protect against

- **Kernel vulnerabilities.** Containers share the host kernel. A kernel
  privilege-escalation bug could cross the boundary; the laboratory reduces
  exposure but cannot eliminate it.
- **Docker daemon compromise.** Docker itself is trusted. The lab does not
  defend the daemon and never runs as root.
- **Malicious NULQ builds.** The binary under test is the project's own code.
  The laboratory is not a malware sandbox.
- **Timing and resource side channels.** Not modelled.
- **Image supply chain.** The base image is pinned by digest; Docker's content
  trust and registry integrity are assumed.

## Host-protection policy

The permanent policy is in `AGENTS.md` §3. In short: no privilege elevation, no
host package or configuration changes, no service or network changes, no
unrelated Docker resources, no global pruning, and no destructive testing
against the host. If an operation could modify the host, it stops and explains
the risk instead of proceeding.

## Deliberate non-actions

- The lab never mounts the Docker socket, even read-only: it grants daemon
  control equivalent to root.
- The lab never uses `--privileged` to make a capability check pass; if a check
  needs capabilities, it is reported unsupported until a safe design exists.
- The lab never executes fixture payloads, sudo rules, units or cron entries.
