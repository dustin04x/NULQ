#!/usr/bin/env bash
# Show NULQ vulnerable-target laboratory resources and artifacts only.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	assert_compose_isolation
	log "vulnerable-target containers (project: nulq-vulntarget):"
	docker ps --filter "label=com.nulq.vulnerable-target=true" --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || true
	log "vulnerable-target images:"
	docker images --filter "label=com.nulq.vulnerable-target=true" --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}" 2>/dev/null || true
else
	log "Docker is unavailable; cannot list resources"
fi

if [ -d "$RESULTS_DIR" ]; then
	log "results:"
	ls -1 "$RESULTS_DIR" 2>/dev/null || true
fi
