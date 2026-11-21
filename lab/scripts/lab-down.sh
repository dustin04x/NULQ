#!/usr/bin/env bash
# Stop and remove NULQ laboratory containers and the project network.
# The image and result artifacts are kept.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

log "stopping laboratory resources (project $COMPOSE_PROJECT_NAME)"
compose down --remove-orphans
log "done; unrelated Docker resources were not touched"
