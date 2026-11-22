# Phase Five: systemd Semantics Certification

**Recorded:** 2026-11-22T09:44:00Z  
**Component:** `internal/platform/linux/systemd/collector.go`, `internal/rules/system/systemd.go`  
**Rule:** NULQ-SYS-005 (Systemd unit lacks security hardening directives)  

## Collector semantics

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Reads .service files from standard systemd directories | `unitPaths`: /etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system, /lib/systemd/system | Certified |
| Only reads .service files | `strings.HasSuffix(entry.Name(), ".service")` filter | Certified |
| Never starts/stops/enables/disables units | No systemd D-Bus or dbus import; file I/O only | Certified |
| Never contacts PID 1 over D-Bus | No dbus connection code | Certified |
| Handles missing directories gracefully | `os.IsNotExist(err)` → continue, no error | Certified |
| Handles unreadable files gracefully | `UnavailableObservation` with error class | Certified |
| Deduplicates overlapping directories | `seen` map keyed by path | Certified |
| Deterministic ordering | `sort.SliceStable` by resource then ID | Certified |

## Rule semantics (NULQ-SYS-005)

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Only flags root-run units | `user != "" && user != "0" && user != "root"` → skip | Certified |
| Only flags units without NoNewPrivileges | `noNewPrivs == "yes" || "true" || "1"` → skip | Certified |
| Severity LOW (not inflated) | `models.SeverityLow` — presence is not vulnerability | Certified |
| Confidence Medium | `models.ConfidenceMedium` — directive observed but runtime state unknown | Certified |
| Evidence-backed | Evidence cites User= and NoNewPrivileges= directive values | Certified |
| Limitations stated | 3 limitations: runtime activation not evaluated, intentional unhardening, other directives not checked | Certified |

## Host protection

Collector runs as unprivileged user. Reads only world-readable systemd unit
files. No writes, no service manipulation, no D-Bus communication.

## No defects found

systemd collector and rule are semantically correct per the Linux privilege
model and AGENTS.md invariants.
