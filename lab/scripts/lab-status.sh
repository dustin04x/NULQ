#!/usr/bin/env bash
# Show the state of NULQ laboratory resources only.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker

echo "== compose services (project $COMPOSE_PROJECT_NAME) =="
compose ps -a || true

echo
echo "== image =="
if image_exists; then
	docker image inspect "$LAB_IMAGE" \
		--format 'name={{.RepoTags}} id={{.Id}} size={{.Size}} created={{.Created}}'
else
	echo "not built ($LAB_IMAGE)"
fi

echo
echo "== nulq binary =="
if [ -x "$NULQ_BINARY" ]; then
	"$NULQ_BINARY" version | sed -n '1p'
else
	echo "missing ($NULQ_BINARY)"
fi

echo
echo "== last results =="
if [ -d "$RESULTS_DIR" ]; then
	ls -1t "$RESULTS_DIR" 2>/dev/null | sed -n '1,12p' || true
else
	echo "no results directory"
fi
