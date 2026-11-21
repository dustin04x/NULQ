# syntax=docker/dockerfile:1
#
# NULQ laboratory target.
#
# The base image is pinned by digest so every run assesses the same userland.
# The real nulq binary is NOT baked in: it is bind-mounted read-only by the
# Compose services, so the laboratory always tests the current build.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

LABEL org.opencontainers.image.title="NULQ Alpine laboratory target"
LABEL org.opencontainers.image.description="Minimal, unprivileged Alpine environment with deterministic privilege-boundary fixtures"
LABEL com.nulq.lab="true"

# One unprivileged assessment account. It has no home, no shell and no
# supplementary privileges; membership in wheel is granted per service by the
# container runtime, never baked into the image.
RUN addgroup -g 10001 -S labuser \
 && adduser -u 10001 -S -D -H -G labuser -s /sbin/nologin labuser

COPY setup-fixtures.sh /usr/local/lib/nulq/setup-fixtures.sh
COPY probe.sh /lab/probe.sh

# Fixtures are created once at build time as root, then the build script is
# removed so the running container cannot regenerate them.
RUN chmod 0555 /usr/local/lib/nulq/setup-fixtures.sh /lab/probe.sh \
 && /usr/local/lib/nulq/setup-fixtures.sh \
 && rm -f /usr/local/lib/nulq/setup-fixtures.sh

USER 10001:10001
WORKDIR /lab

# The default command is harmless; services override it with a scan or probe.
CMD ["version"]
