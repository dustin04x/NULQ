#!/usr/bin/env bash
# Show logs for NULQ laboratory containers only.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker

containers="$(compose ps -a -q 2>/dev/null || true)"
if [ -z "$containers" ]; then
	log "no laboratory containers exist; run make lab-up or make lab-test"
	exit 0
fi
compose logs --no-color --tail 200
