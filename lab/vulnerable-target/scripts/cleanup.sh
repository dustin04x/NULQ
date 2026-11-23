#!/usr/bin/env bash
# Remove only NULQ vulnerable-target laboratory resources.
#
# Never runs global Docker pruning. Containers are selected by both the compose
# project label and the com.nulq.vulnerable-target label; the image is removed
# only if it carries the com.nulq.vulnerable-target label. Results are kept.
# Never touches nulq-lab resources.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
	log "Docker is unavailable; nothing can be removed"
	exit 0
fi
assert_compose_isolation

log "removing vulnerable-target containers and network"
compose down --remove-orphans || true

ids="$(vt_container_ids)"
if [ -n "$ids" ]; then
	# shellcheck disable=SC2086
	docker rm -f $ids >/dev/null
	log "removed leftover NULQ vulnerable-target containers"
fi

if docker image inspect "$VT_IMAGE" >/dev/null 2>&1; then
	label="$(docker image inspect "$VT_IMAGE" --format '{{index .Config.Labels "com.nulq.vulnerable-target"}}' 2>/dev/null || true)"
	if [ "$label" = "true" ]; then
		docker image rm "$VT_IMAGE" >/dev/null
		log "removed image $VT_IMAGE"
	else
		log "kept $VT_IMAGE: it is not labelled com.nulq.vulnerable-target=true"
	fi
fi

log "cleanup complete; results in $RESULTS_DIR were kept"
log "no global prune was run and no unrelated resource was touched"
