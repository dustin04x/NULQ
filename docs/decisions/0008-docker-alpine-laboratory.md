# ADR 0008 — Docker + Alpine as the reproducible assessment laboratory

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

NULQ's detection rules are exercised by unit and fixture tests on the
development host, but those tests cannot prove that the shipped binary behaves
correctly on a *different* Linux system, nor that it works unprivileged against
root-owned privileged files. The owner will not install a second distribution
or maintain a VM, and the primary workstation must not be used as a test target.

The laboratory must be automated, reproducible, lightweight, isolated from the
host, and honest about what a minimal container can and cannot represent.

## Decision

Use **Docker Compose** with a single **Alpine Linux 3.22** target image, pinned
by digest (`alpine:3.22@sha256:49340b34…`).

- The image is built from `lab/docker/alpine/Dockerfile`, contains only
  BusyBox, one unprivileged account and deterministic fixtures.
- The real `bin/nulq` binary is bind-mounted read-only; the binary is never
  rebuilt inside the container and the repository is never mounted.
- Every service runs with uid/gid 10001, all capabilities dropped,
  `no-new-privileges`, a read-only root filesystem, a size-limited
  `noexec,nosuid,nodev` `/tmp`, `network_mode: none` and no host namespaces.
- Compose project `nulq-lab` and `com.nulq.lab=true` labels make cleanup
  targeted; no global Docker pruning is used.
- The laboratory runs the real binary and validates its JSON against the
  published schema; it does not reimplement or mock detection.

Alpine was chosen over Debian/Ubuntu because it is ~12 MB, has no systemd or
package-manager side effects during tests, starts in under a second, and makes
the distinction between *live observation* and *synthetic fixture* obvious.

## Consequences

- Fast, disposable runs on any machine with Docker; no VM or ISO.
- Alpine cannot represent systemd, PAM, SELinux, sudo policy or a distribution's
  SUID inventory. Those areas use synthetic fixtures and are reported as
  unsupported scenarios until their rules exist. Documentation states this.
- The container shares the Docker host kernel; sysctl observations describe
  that kernel, not bare metal. Reports record the container context.
- Docker becomes a hard prerequisite for `make lab-test`. The tooling detects
  its absence and stops without attempting to install it.
- Baseline scans mount an empty tmpfs over `/lab/fixtures` so fixture findings
  cannot be mistaken for live Alpine observations.

## Alternatives considered

- **QEMU/cloud image VMs:** closer to a real distribution, but slow, heavy,
  requires images and networking, and still needs manual setup.
- **chroot/podman-only:** less portable and lacks the uniform isolation and
  inspection surface Docker Compose provides.
- **Mocked scanner in tests:** rejected outright; it would test the mock, not
  the product.
- **Debian slim image:** represents sudo/systemd better but is larger, slower
  and still not a faithful server; the synthetic-fixture model is retained for
  those checks regardless.
