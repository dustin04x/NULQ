# Phase Nine: Failure Injection and Hostile Inputs

**Recorded:** 2026-11-22T09:48:00Z  

## Failure scenarios tested

| Scenario | Result | Behavior |
|----------|--------|----------|
| Scan root `/nonexistent` | Exit 0 | Root marked `unavailable`; 4 rules skipped with "missing observations" reason; no crash |
| `rules list --format json` | Exit 0 | All 20 rules with full metadata |
| Scan root `/tmp` | Exit 0 | Normal scan, 977 findings, coverage partial |
| Missing Docker (lab) | Reported | Lab detects missing Docker and reports prerequisite, does not install |
| Container failure (lab) | Handled | Lab cleanup removes only its own containers |

## Error class coverage

All error classes from `internal/core/errors` are used:
- `permission_denied`: unreadable files/directories
- `not_found`: missing paths (nonexistent roots)
- `unavailable`: cannot observe at all
- `unsupported`: unsupported kernel features
- `malformed_input`: bad configuration format
- `timeout`: collector/rule timeouts
- `canceled`: context cancellation
- `resource_exhausted`: process budget exceeded
- `internal`: unexpected failures

## Hostile input handling

| Input | Result |
|-------|--------|
| PATH with empty entries | NULQ-FS-003 reports empty entry as LOW |
| PATH with relative entries | NULQ-FS-003 reports relative entry as LOW |
| PATH with unknown writability | Skipped (not false positive — fixed A-001) |
| SUID bit without execute bit | Not treated as vulnerability (inert) |
| World-writable sticky directory | Not reported (protected entries) |
| Unreadable ACL | Treated as unknown, not assumed |
| Missing /etc/sudoers | Rule skipped, not error |
| Missing systemd directories | Collector continues, not error |

## No silent failures

Unreadable or unsupported data becomes an observation with a status and error
class, reflected in coverage. No errors are silently swallowed.

## No defects found

Failure paths are handled gracefully with proper error classification.
No crashes, no silent failures, no false positives from hostile inputs.
