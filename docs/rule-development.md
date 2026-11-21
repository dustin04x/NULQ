# Rule development

A rule is a small, testable interpretation of shared observations. This guide
describes the contract and the judgement expected from contributors.

## 1. Decide what the rule establishes

Write the security statement in one sentence, including its limits. Example:

> A PATH directory is writable by the current user while owned by another
> account, so command resolution can be influenced by the wrong party.

If the sentence requires words like "could maybe", the rule is not ready.

## 2. Declare metadata

```go
func (r myRule) Metadata() models.RuleMetadata {
    return models.RuleMetadata{
        ID:          "NULQ-FS-004",
        Version:     "1.0.0",
        Name:        "Readable summary",
        Description: "What the rule checks and why it matters.",
        Category:    "path-hijack",
        Module:      "filesystem",
        Severity:    models.SeverityHigh,
        Confidence:  models.ConfidenceHigh,
        Required:    []models.Kind{models.KindPathEntry, models.KindExecutionContext},
        Platforms:   []string{"linux"},
    }
}
```

Rules:

- IDs are permanent. Never reuse or renumber one.
- `Required` must list every kind the rule reads. The engine skips the rule when
  a kind is missing; do not duplicate that logic.
- `Module` must exist in an existing module directory.
- Metadata is validated at startup; an invalid rule is a build-time failure.

## 3. Consume observations, not the system

- Never call `os.Stat`, `os.ReadFile`, `exec.Command` or walk directories.
- Use `obs.ByKind(kind)` and attributes. If the data you need is missing, add a
  collector observation in M2/M3 rather than reading it in the rule.
- Cross-reference other kinds deliberately (for example a directory that is
  also a PATH entry) and state that reasoning in the finding.

## 4. Emit evidence for every claim

```go
builder := evidence.New()
id := builder.AddExpected(parameter, models.AttrValue, "1", "Current kernel value.")
finding.AddEvidence(id)
```

- Cite the observation and field the conclusion depends on.
- Record the expected value for hardening checks.
- Do not cite unrelated attributes to inflate a finding.
- The engine rejects a finding with no evidence or an unknown reference.

## 5. Write the finding honestly

Each finding needs:

- a stable title (no timestamps or counts);
- an explanation of the technical mechanism;
- a potential impact that distinguishes fact from inference;
- remediation relative to the observed state;
- limitations naming what was not assessed;
- references when an external authority supports the claim.

Severity guidance:

| Severity | Use when |
|---|---|
| CRITICAL | Immediate, unconditional path from unprivileged user to root |
| HIGH | Direct privilege-boundary crossing with few preconditions |
| MEDIUM | Real boundary crossing requiring configuration or timing context |
| LOW | Hardening gap or inventory item with a plausible path |
| INFO | Useful context, not a weakness |

Confidence is separate: facts observed directly are HIGH even if the exposure
is LOW. Never raise severity to make a finding noticeable.

## 6. Test

Required cases:

- positive: the condition is detected with the expected severity;
- negative: a benign neighbouring configuration produces nothing;
- unavailable: missing or unreadable observations do not produce a finding;
- evidence: every emitted finding passes `Validate` and cites returned
  evidence;
- determinism: the same input yields the same finding ID.

Use `internal/engine/store` to build observation sets. Table tests are
preferred; include the observation attributes verbatim so failures are easy to
diagnose.

## 7. Register and document

- Add the constructor to `internal/rules/rules.go`.
- Add the rule to the README table.
- Add a changelog entry.
- If you introduce new severity reasoning, document it in
  `docs/linux-privilege-model.md`.
- If the rule needs a new observation kind, follow
  `docs/observation-model.md`.

## 8. Review checklist

- Does it detect a real security condition, not an unusual configuration?
- Is the severity defensible without exploit knowledge?
- Does it work unprivileged?
- What happens when data is unavailable?
- Are symlinks handled safely (never by their own mode)?
- Could it flood the report on a normal host?
- Are IDs and ordering stable?
- Do tests validate behaviour rather than implementation details?
- Is the rule's limitation statement accurate?

## Anti-patterns

- "Found a SUID file, therefore vulnerable."
- Reading the filesystem inside `Evaluate`.
- Emitting one finding per benign inventory item at HIGH.
- Citing an observation as evidence when the conclusion came from elsewhere.
- Using time or map iteration in an ID or title.
- Adding a rule without a negative test.
