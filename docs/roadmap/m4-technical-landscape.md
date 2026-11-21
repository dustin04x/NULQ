# M4 Technical Landscape

**NULQ — M4 architecture & engineering blueprint**

This document surveys relevant Linux security-assessment concepts and compares
architectural ideas NULQ could adopt in M4. It distinguishes externally researched
facts from design recommendations and explains, for each borrowed concept, the
underlying idea, relevance, adaptation, risks, and why it is preferable to a simpler
alternative. No other project's architecture is copied and no proprietary code is
reproduced.

## Scope of the survey

The survey covers:
- Linux privilege-boundary analysis
- Linux process and filesystem security
- Attack-surface analysis
- Relationship- and graph-based security analysis
- Evidence-driven security detection
- Static vs dynamic security analysis
- Configuration auditing
- Container security posture assessment
- Finding confidence and explainability

## Observed principles from established practice

### 1. Observation-first, read-only enumeration
**Idea:** Collect normalized facts about the system without executing or modifying
anything; let detection rules reason over the shared fact base.
**Relevance:** This is NULQ's existing architecture (observation → relationship →
evaluation → evidence → finding) and its defining characteristic.
**Adaptation:** Already implemented (collectors, store, rules). Keep.
**Risks:** None beyond collection incompleteness (unreadable paths reported as
unavailable, never bypassed).
**Vs simpler alternative:** A shell-script enumerator would be easier but not
normalized, typed, reproducible, or evidence-traceable. NULQ's model is strictly
better for defensible findings.

### 2. Content-stable identifiers
**Idea:** Derive observation/finding IDs from content (hash of kind+resource) so
identical system state yields identical IDs across scans.
**Relevance:** NULQ already does this for observations (`ObservationID`) and findings
(`NewFinding` = rule ID + resource + title). It is a strength.
**Adaptation:** Keep; extend to entities and relationships in M4.
**Risks:** Hash collisions are astronomically unlikely for SHA-256 truncated to 6 bytes;
acceptable for internal correlation but not for cryptographic unforgeability (not a
goal).
**Vs simpler alternative:** Monotonically increasing IDs are simpler but nondeterministic
across scans and processes, breaking reproducibility. Content IDs are correct here.

### 3. Explicit UNKNOWN / three-valued permission logic
**Idea:** Permission decisions return ALLOWED / DENIED / UNKNOWN; UNKNOWN never collapses
to ALLOWED; missing ACL state is unknown, not a mode-bit fallback.
**Relevance:** NULQ's ACL package (`acl.Access` = Allowed/Denied/Unknown) and collector
(`writable_by_current_user=unknown` when ACL unreadable) implement this correctly.
**Adaptation:** Keep; extend to mount-context and process-identity UNKNOWN handling.
**Risks:** Conservative UNKNOWN can reduce finding count (fewer positives), but that is
the intended tradeoff for a read-only assessor.
**Vs simpler alternative:** Mode-bit-only evaluation is simpler but wrong in the presence
of ACLs (a file can be mode 0777 yet an ACL denies a specific named user write).
NULQ's ACL-aware model is correct.

### 4. Sticky-bit-aware directory replacement semantics
**Idea:** Directory write+execute permission does not imply entry replacement when the
sticky bit is set and the entrant is neither directory owner, entry owner, nor root.
**Relevance:** `acl.CanReplaceEntry` and `replaceability()` in the writable-parent rule
implement this correctly.
**Adaptation:** Keep; make it a reusable relationship primitive in M4.
**Risks:** None identified; this matches `unlink(2)` semantics.
**Vs simpler alternative:** Treating world-writable as always-replaceable overstates
exposure (false positive on `/tmp`-style sticky dirs). NULQ is correct.

### 5. Mount-flag contextualization, not universal protection
**Idea:** `nosuid`/`noexec`/`nodev`/`ro` constrain specific execution/device behaviors;
they do not make a mount "safe" generally and must be associated with the correct path.
**Relevance:** NULQ's mount flags rule (`NULQ-FS-004`) and writable-parent rule treat
flags contextually and never treat nosuid as a substitute for file integrity.
**Adaptation:** Keep; M4 mount-context correlation should preserve this.
**Risks:** Associating flags to the wrong path (naive prefix matching) causes false
assurance. NULQ's longest-prefix `ResolveMount` avoids this.
**Vs simpler alternative:** Treating any nosuid mount as fully safe is a known false
negative. NULQ's contextual model is correct.

### 6. Evidence-backed findings with referential integrity
**Idea:** Every finding cites observation IDs and fields; invalid references are
rejected; evidence never contains secrets.
**Relevance:** NULQ's `aggregation.Merge`, `validateRuleOutput`, and `Finding.Validate()`
enforce this.
**Adaptation:** Keep; extend to relationship evidence and cross-rule evidence reuse in
M4.
**Risks:** Strict referential integrity can drop findings when evidence is missing —
correct, not a defect.
**Vs simpler alternative:** Emitting findings with dangling evidence references is easier
but makes reports unverifiable. NULQ's model is correct.

### 7. Conservative severity: presence is not vulnerability
**Idea:** A SUID binary in a distribution directory is inventory; a world-writable
directory on PATH is LOW unless a privileged consumer is demonstrated.
**Relevance:** NULQ's detection model (README) and rule severities implement this.
**Adaptation:** Keep as an explicit M4 design principle.
**Risks:** Under-reporting relative to scanners that flag everything suspicious; that is
the intended tradeoff.
**Vs simpler alternative:** Flagging every SUID binary as HIGH produces noise and
false positives. NULQ's model is defensible.

## Concepts evaluated but NOT adopted for M4

| Concept | Why not adopted |
|---|---|
| Dynamic binary execution / exploit verification | NULQ is read-only; executing discovered binaries is forbidden by its safety policy. |
| Privilege escalation / persistence techniques | Out of scope; NULQ is an assessment framework, not an exploitation tool. |
| Credential dumping / harvesting | Forbidden; collectors never read secrets, env, cmdline, or memory. |
| Container escape techniques | Forbidden and architecturally contrary to read-only assessment. |
| Database / telemetry / network listeners | Forbidden by security restrictions; no persistent state or network use. |
| Plugin loading / third-party runtime | Would introduce supply-chain risk and non-determinism; std-lib-only is a strength. |
| CVE / exploitability inference from version strings | Explicitly forbidden; version presence ≠ exploitability. |

## Conclusion

NULQ's existing architecture already embodies the soundest ideas from the landscape:
observation-first analysis, content-stable IDs, three-valued permission logic,
sticky-bit-aware replacement semantics, contextual mount flags, evidence-backed
findings with referential integrity, and conservative severity. M4 should extend this
foundation (entities, validated relationships, correlation findings, deterministic
serialization) rather than replace it. The primary gap is the missing M3.5 acceptance
of the relationship and correlation layer, which M4 must not assume is sound.
