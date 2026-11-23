#!/usr/bin/env bash
# Show logs for NULQ vulnerable-target containers.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation

compose logs "$@"
