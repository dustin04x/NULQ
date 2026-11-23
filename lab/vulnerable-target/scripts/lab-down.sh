#!/usr/bin/env bash
# Stop vulnerable-target containers and the project network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

compose down
log "vulnerable-target containers stopped"
