#!/usr/bin/env bash
# Run the complete NULQ vulnerable-target laboratory: isolation proof, five
# real scans, schema validation, scenario evaluation and reports.
#
# Requires Docker. Requires no manual interaction.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_host_guard
require_docker
assert_compose_isolation
require_binary
ensure_results

run_scan() {
	local service="$1" destination="$2"
	log "running $service"
	compose run --rm -T "$service" >"$destination"
	[ -s "$destination" ] || die "$service produced no output (see $destination)"
}

log "probing container isolation"
compose run --rm -T vuln-probe >"$RESULTS_DIR/isolation.json"
[ -s "$RESULTS_DIR/isolation.json" ] || die "isolation probe produced no output"

run_scan nulq-baseline "$RESULTS_DIR/scan.json"
run_scan nulq-fixtures "$RESULTS_DIR/scan-fixtures.json"
run_scan nulq-path "$RESULTS_DIR/scan-path.json"
run_scan nulq-identity "$RESULTS_DIR/scan-identity.json"
run_scan nulq-app "$RESULTS_DIR/scan-app.json"

# Independent parser cross-check. The Go validator is authoritative and always
# runs; when Python plus jsonschema is available it provides a second opinion
# from an unrelated implementation.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import jsonschema' >/dev/null 2>&1; then
	log "cross-checking reports with python jsonschema"
	python3 "$VT_DIR/scripts/validate-schema.py" "$SCHEMA_FILE" \
		"$RESULTS_DIR/scan.json" \
		"$RESULTS_DIR/scan-fixtures.json" \
		"$RESULTS_DIR/scan-path.json" \
		"$RESULTS_DIR/scan-identity.json" \
		"$RESULTS_DIR/scan-app.json"
else
	log "python jsonschema not available; skipping the independent cross-check"
fi

log "validating scenarios"
cd "$PROJECT_ROOT"
go run ./lab/verify \
	-results "$RESULTS_DIR" \
	-manifest "$VT_DIR/scenarios/manifest.json" \
	-schema "$SCHEMA_FILE"
