#!/usr/bin/env bash
# Build the real nulq binary and the pinned Alpine vulnerable-target image.
#
# Usage: lab/vulnerable-target/build.sh [--no-cache]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation
ensure_results

log "building the real nulq binary"
(cd "$PROJECT_ROOT" && make build)
require_binary

log "building $VT_IMAGE"
if [ "${1:-}" = "--no-cache" ]; then
	compose build --no-cache vuln-target
else
	compose build vuln-target
fi

image_id="$(docker image inspect "$VT_IMAGE" --format '{{.Id}}')"
base_digest="$(sed -n 's/^FROM alpine:[^ ]*@\(sha256:[0-9a-f]*\).*/\1/p' "$VT_DIR/Dockerfile")"
base_tag="$(sed -n 's/^FROM \(alpine:[0-9.]*\)@.*/\1/p' "$VT_DIR/Dockerfile")"
nulq_version="$("$NULQ_BINARY" version | tr -d '"' | sed -n '1p')"

printf '{"image":"%s","image_id":"%s","base_image":"%s","base_digest":"%s","nulq_version":"%s","built_at":"%s"}\n' \
	"$VT_IMAGE" "$image_id" "$base_tag" "$base_digest" "$nulq_version" \
	"$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RESULTS_DIR/image.json"

log "image ready: $VT_IMAGE ($image_id)"
log "base digest: $base_digest"
