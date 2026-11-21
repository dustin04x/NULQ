package models

import (
	"fmt"
	"strings"
)

// EvaluationOutcome describes the result of a correlation evaluation.
// An EvaluationOutcome indicates the strength of evidence supporting a
// correlation relationship. It is deliberately separate from severity: every
// finding also carries Confidence and explicit Limitations.
type EvaluationOutcome string

const (
	// EvaluationConfirmed indicates the relationship is confirmed by observed evidence.
	EvaluationConfirmed EvaluationOutcome = "confirmed"
	// EvaluationPotential indicates a potential relationship that is not yet fully confirmed.
	EvaluationPotential EvaluationOutcome = "potential"
	// EvaluationInsufficient indicates there is insufficient evidence to draw a conclusion.
	EvaluationInsufficient EvaluationOutcome = "insufficient"
	// EvaluationContradicted indicates that contradictory observations were found.
	EvaluationContradicted EvaluationOutcome = "contradicted"
	// EvaluationUnknown indicates the relationship cannot be determined.
	EvaluationUnknown EvaluationOutcome = "unknown"
)

// AllEvaluationOutcomes returns every evaluation outcome.
func AllEvaluationOutcomes() []EvaluationOutcome {
	return []EvaluationOutcome{EvaluationConfirmed, EvaluationPotential, EvaluationInsufficient, EvaluationContradicted, EvaluationUnknown}
}

// Valid reports whether s is a known evaluation outcome.
func (s EvaluationOutcome) Valid() bool {
	switch s {
	case EvaluationConfirmed, EvaluationPotential, EvaluationInsufficient, EvaluationContradicted, EvaluationUnknown:
		return true
	}
	return false
}

// Rank returns an ordinal for the evaluation outcome, or -1 when unknown.
func (s EvaluationOutcome) Rank() int {
	rank := map[EvaluationOutcome]int{
		EvaluationConfirmed:    4,
		EvaluationPotential:    3,
		EvaluationInsufficient: 2,
		EvaluationContradicted: 1,
		EvaluationUnknown:      0,
	}
	if r, ok := rank[s]; ok {
		return r
	}
	return -1
}

// Less reports whether s ranks below t. Unknown never ranks below anything.
func (s EvaluationOutcome) Less(t EvaluationOutcome) bool {
	if !s.Valid() || !t.Valid() {
		return false
	}
	return s.Rank() < t.Rank()
}

// String renders the evaluation outcome as a string.
func (s EvaluationOutcome) String() string {
	return string(s)
}

// Severity describes the assessed security significance of a finding.
// Severity is a judgement a rule makes from observed facts. It is never a
// verdict of exploitability: every finding also carries Confidence and
// explicit Limitations.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

var severityOrder = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// AllSeverities returns every severity from least to most severe.
func AllSeverities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	_, ok := severityOrder[s]
	return ok
}

// Rank returns an ordinal for the severity, or -1 when unknown.
func (s Severity) Rank() int {
	if rank, ok := severityOrder[s]; ok {
		return rank
	}
	return -1
}

// AtLeast reports whether s is at or above min. Unknown severities never
// satisfy the comparison.
func (s Severity) AtLeast(min Severity) bool {
	if !s.Valid() || !min.Valid() {
		return false
	}
	return s.Rank() >= min.Rank()
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(value string) (Severity, error) {
	s := Severity(strings.ToUpper(strings.TrimSpace(value)))
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q (expected one of %s)", value, strings.Join(severityNames(), ", "))
	}
	return s, nil
}

func severityNames() []string {
	names := make([]string, 0, len(severityOrder))
	for _, s := range AllSeverities() {
		names = append(names, string(s))
	}
	return names
}

// Confidence expresses how strongly the available evidence supports a
// finding. It is deliberately separate from severity: a HIGH severity
// weakness observed with LOW confidence is still actionable, but it is
// reported honestly.
type Confidence string

const (
	// ConfidenceLow expresses that the available evidence is weak or limited.
	ConfidenceLow Confidence = "LOW"
	// ConfidenceMedium expresses that the available evidence is moderate.
	ConfidenceMedium Confidence = "MEDIUM"
	// ConfidenceHigh expresses that the available evidence is strong.
	ConfidenceHigh Confidence = "HIGH"
)

var confidenceOrder = map[Confidence]int{
	ConfidenceLow:    0,
	ConfidenceMedium: 1,
	ConfidenceHigh:   2,
}

// Valid reports whether c is a known confidence.
func (c Confidence) Valid() bool {
	_, ok := confidenceOrder[c]
	return ok
}

// Rank returns an ordinal for the confidence, or -1 when unknown.
func (c Confidence) Rank() int {
	if rank, ok := confidenceOrder[c]; ok {
		return rank
	}
	return -1
}
