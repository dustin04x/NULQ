#!/usr/bin/env bash
# Remove only NULQ laboratory resources.
#
# Never runs global Docker pruning. Containers are selected by both the compose
# project label and the com.nulq.lab label; the image is removed only if it
# carries the com.nulq.lab label. Results are kept.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
	log "Docker is unavailable; nothing can be removed"
	exit 0
fi
assert_compose_isolation

log "removing laboratory containers and network"
compose down --remove-orphans || true

ids="$(nulq_container_ids)"
if [ -n "$ids" ]; then
	# shellcheck disable=SC2086
	docker rm -f $ids >/dev/null
	log "removed leftover NULQ containers"
fi

if image_exists; then
	label="$(docker image inspect "$LAB_IMAGE" --format '{{index .Config.Labels "com.nulq.lab"}}' 2>/dev/null || true)"
	if [ "$label" = "true" ]; then
		docker image rm "$LAB_IMAGE" >/dev/null
		log "removed image $LAB_IMAGE"
	else
		log "kept $LAB_IMAGE: it is not labelled com.nulq.lab=true"
	fi
fi

log "cleanup complete; results in $RESULTS_DIR were kept"
log "no global prune was run and no unrelated resource was touched"
