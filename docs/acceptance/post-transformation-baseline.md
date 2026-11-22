# NULQ Post-Transformation Acceptance Baseline

**Recorded:** 2026-11-22T09:35:00Z  
**Repository:** https://github.com/dustin04x/NULQ  
**Working directory:** /home/dustin/Projects/NULQ  
**Branch:** master (synced with origin/master)  
**Commit:** c278284  
**Go:** go1.27.4-X:nodwarf5 linux/amd64  
**Module:** github.com/dustin04x/nulq  
**Working tree:** clean  
**Untracked files:** none  
**Tracked files:** 200  

## Revision history (last 5 commits)

```
c278284 Sync MISSION.md and ROADMAP.md with implemented 20-rule codebase
6f05b09 Make README more minimal and focused
af5b705 Add SSH/auth hardening rules (NULQ-ID-004, NULQ-ID-006, NULQ-SYS-009)
0e1fa23 Add lab scenarios for NULQ-SYS-007 and NULQ-SYS-008
8dfe647 Complete observation model docs, collector tests, and changelog
```

## Code state summary

- **Rules registered:** 20 (see `internal/rules/rules.go`)
- **Observation kinds:** 8 new kinds added during transformation
- **Lab scenarios:** 39 total (34 supported, 5 unsupported)
- **Lab test result:** 34/34 pass, 5 unsupported
- **Verification gates:** all pass (gofmt, go vet, go test, go test -race, make build, arm64 cross-compile)

## Documented defects (P0/P1)

| ID | File | Severity | Description |
|----|------|----------|-------------|
| A-001 | `internal/rules/filesystem/path_entry.go:89-98` | P1 | `writable == "unknown"` falls through to the reporting branch, producing a false positive "writable by current user but owned by another account" finding when writability is actually unknown |
| A-002 | `internal/engine/correlation/engine.go:180-185` | P1 | `containsPath()` uses naive string-prefix match `path[:len(mountPoint)] == mountPoint` without boundary check; `/various` matches against `/var` |
| A-003 | `internal/engine/correlation/engine.go:352-360` | P1 | `evaluateCOR002()` creates self-referential relationships where `Source == Target == inode` |
| A-004 | `internal/engine/correlation/engine.go:738-798` | P1 | `evaluateCOR005()` creates relationships with empty `Source`/`Target` IDs and empty `Evidence` |
| A-005 | `AGENTS.md` rule 10 | P2 | Claims correlation engine is not implemented, but `internal/engine/correlation/engine.go` exists and works — documentation/code contradiction |

## Acceptance campaign phases

1. Post-transformation baseline (this document)
2. Requirement certification
3. Application walkthrough (binary smoke tests)
4. Adversarial observation model audit
5. Relationship engine red-team (defect fixes A-001..A-004)
6. systemd semantics certification
7. Rule-by-rule adversarial validation
8. End-to-end evidence chain verification
9. Determinism and reproducibility
10. Failure injection and hostile inputs
11. Laboratory independence
12. Performance and resource certification
13. Full automated quality gates
14. Document actual results (all acceptance docs)
15. Git delivery
16. Final acceptance decision

## Deliverables

12 acceptance documents under `docs/acceptance/`:
1. `post-transformation-baseline.md` (this document)
2. `01-requirement-certification.md`
3. `02-application-walkthrough.md`
4. `03-observation-model-audit.md`
5. `04-relationship-engine-red-team.md`
6. `05-systemd-certification.md`
7. `06-rule-by-rule-validation.md`
8. `07-evidence-chain-verification.md`
9. `08-determinism-reproducibility.md`
10. `09-failure-injection-hostile-inputs.md`
11. `10-laboratory-independence.md`
12. `11-performance-quality-gates.md`
13. `12-final-acceptance-verdict.md`

## Host protection status

No host modifications made or required for this phase. All work confined to the NULQ repository. No sudo, doas, su, package installs, host config changes, or Docker socket mounts used.
