#!/usr/bin/env bash
# Rebuild the vulnerable-target image from scratch.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

compose down --remove-orphans || true

if docker image inspect "$VT_IMAGE" >/dev/null 2>&1; then
	label="$(docker image inspect "$VT_IMAGE" --format '{{index .Config.Labels "com.nulq.vulnerable-target"}}' 2>/dev/null || true)"
	if [ "$label" = "true" ]; then
		docker image rm "$VT_IMAGE" >/dev/null
		log "removed existing image $VT_IMAGE"
	fi
fi

compose build --no-cache vuln-target
log "vulnerable-target image rebuilt: $VT_IMAGE"
