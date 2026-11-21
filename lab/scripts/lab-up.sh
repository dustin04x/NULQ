#!/usr/bin/env bash
# Start the long-running laboratory target for manual inspection.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation
require_binary

if ! image_exists; then
	log "image missing; building it first"
	"$LAB_DIR/scripts/lab-build.sh"
fi

log "starting lab-target"
compose up -d lab-target
compose ps
log "inspect with: docker compose -p nulq-lab exec lab-target sh"
