#!/usr/bin/env bash
# Shared helpers for NULQ vulnerable-target laboratory scripts.
#
# Every script sources this file. It enforces the host-protection policy before
# any Docker command runs: the lab runs as the unprivileged owner account, and
# the Compose file is checked for forbidden isolation-breaking settings.
#
# This is independent of lab/scripts/lib.sh. It never shares resource
# ownership or cleanup scope with nulq-lab.

set -euo pipefail

VT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(cd "$VT_DIR/../.." && pwd)"
RESULTS_DIR="$VT_DIR/results"
COMPOSE_FILE="$VT_DIR/compose.yaml"
SCHEMA_FILE="$PROJECT_ROOT/schemas/nulq-report-v1.schema.json"

VT_IMAGE="${VT_IMAGE:-nulq-vulntarget/alpine-target:3.22}"
export VT_IMAGE
export NULQ_BINARY="${NULQ_BINARY:-$PROJECT_ROOT/bin/nulq}"
export COMPOSE_PROJECT_NAME="nulq-vulntarget"

log() { printf '[nulq-vulntarget] %s\n' "$*"; }
die() {
	printf '[nulq-vulntarget] error: %s\n' "$*" >&2
	exit 1
}

compose() {
	docker compose --project-name "$COMPOSE_PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

# The lab must never run as root: root-owned build artifacts in the repository
# would change host state and hide permission bugs.
require_host_guard() {
	[ "$(id -u)" -ne 0 ] || die "refusing to run as root; run as the unprivileged owner account"
	case "$PROJECT_ROOT" in
	/ | "") die "unexpected project root: $PROJECT_ROOT" ;;
	esac
	[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE"
}

require_docker() {
	command -v docker >/dev/null 2>&1 ||
		die "docker is not installed; this project will not install it"
	docker info >/dev/null 2>&1 ||
		die "the Docker daemon is not reachable; start it yourself, this project will not"
	docker compose version >/dev/null 2>&1 ||
		die "Docker Compose v2 is required (docker compose)"
}

require_binary() {
	[ -x "$NULQ_BINARY" ] || die "nulq binary not found or not executable: $NULQ_BINARY (run make build)"
}

ensure_results() {
	mkdir -p "$RESULTS_DIR"
}

# Refuse to run with a Compose file that weakens the security model.
assert_compose_isolation() {
	local forbidden
	for forbidden in "privileged: true" "network_mode: host" "pid: host" \
		"ipc: host" "uts: host" "/var/run/docker.sock" "cap_add:" \
		"source: /" "target: /etc" "target: /usr" "target: /var" \
		"target: /root" "target: /proc" "target: /sys" "target: /home"; do
		if grep -Fq -- "$forbidden" "$COMPOSE_FILE"; then
			die "compose file contains a forbidden setting: $forbidden"
		fi
	done
	grep -Fq "read_only: true" "$COMPOSE_FILE" || die "compose file must set read_only: true"
	grep -Fq "no-new-privileges:true" "$COMPOSE_FILE" || die "compose file must set no-new-privileges"
	grep -Fq "cap_drop:" "$COMPOSE_FILE" || die "compose file must drop capabilities"
	grep -Fq "network_mode: none" "$COMPOSE_FILE" || die "compose file must disable networking"
}

image_exists() {
	docker image inspect "$VT_IMAGE" >/dev/null 2>&1
}

# Only ever remove resources that are provably NULQ vulnerable-target's.
vt_container_ids() {
	docker ps -aq \
		--filter "label=com.nulq.vulnerable-target=true" \
		--filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" 2>/dev/null || true
}
