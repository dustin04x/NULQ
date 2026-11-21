#!/usr/bin/env bash
# Recreate the laboratory from its original image definition and fixtures.
# Only NULQ-labelled project resources and the lab image are affected.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

log "removing laboratory containers and network"
compose down --remove-orphans

if image_exists; then
	log "excluding the current lab image from the rebuild"
fi
LAB_IMAGE="$LAB_IMAGE" "$LAB_DIR/scripts/lab-build.sh" --no-cache
log "laboratory reset from lab/docker/alpine/Dockerfile"
