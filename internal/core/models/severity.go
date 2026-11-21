package models

import (
	"fmt"
	"strings"
)

// Severity describes the assessed security significance of a finding.
//
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
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
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
