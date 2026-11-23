#!/usr/bin/env bash
# Start the long-running vulnerable target for manual inspection.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

compose up -d vuln-target
log "vulnerable target running (project: nulq-vulntarget)"
