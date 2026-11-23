# syntax=docker/dockerfile:1
#
# NULQ vulnerable-target laboratory target.
#
# Deliberately misconfigured Alpine environment for read-only NULQ assessment.
# The real nulq binary is NOT baked in: it is bind-mounted read-only by the
# Compose service, so the laboratory always tests the current build.
#
# All test binaries are inert copies of /bin/busybox: NULQ never executes them.
# No exploit payloads, shells, credential access, persistence, or
# privilege-escalation functionality is included.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

LABEL org.opencontainers.image.title="NULQ vulnerable-target laboratory"
LABEL org.opencontainers.image.description="Deliberately misconfigured Alpine environment with privilege-boundary fixtures for NULQ assessment"
LABEL com.nulq.vulnerable-target="true"

# One unprivileged assessment account. It has no home, no shell and no
# supplementary privileges baked into the image.
RUN addgroup -g 10001 -S vulntarget \
 && adduser -u 10001 -S -D -H -G vulntarget -s /sbin/nologin vulntarget

COPY build-fixtures.sh /usr/local/lib/nulq/build-fixtures.sh
COPY probe.sh /lab/probe.sh

# Fixtures are created once at build time as root, then the build script is
# removed so the running container cannot regenerate them.
RUN chmod 0555 /usr/local/lib/nulq/build-fixtures.sh /lab/probe.sh \
 && /usr/local/lib/nulq/build-fixtures.sh \
 && rm -f /usr/local/lib/nulq/build-fixtures.sh

USER 10001:10001
WORKDIR /lab

# The default command is harmless; services override it with a scan.
CMD ["version"]
