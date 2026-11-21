#!/usr/bin/env python3
"""Independent cross-check of NULQ reports against the published schema.

This script is optional. The Go validator in internal/lab is authoritative and
always runs. When python3 and the jsonschema package are available, lab-test.sh
invokes this file as a second opinion from an unrelated implementation.
"""

import json
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - guarded by the caller
    sys.exit("jsonschema is not installed")


def main() -> int:
    if len(sys.argv) < 3:
        sys.exit("usage: validate-schema.py SCHEMA.json REPORT.json...")

    with open(sys.argv[1], encoding="utf-8") as handle:
        schema = json.load(handle)
    validator = Draft202012Validator(schema)

    failed = False
    for path in sys.argv[2:]:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
        if not errors:
            print(f"schema OK: {path}")
            continue
        failed = True
        for error in errors[:10]:
            location = ".".join(str(part) for part in error.absolute_path) or "$"
            print(f"{path}: {location}: {error.message}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
