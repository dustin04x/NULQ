package models

import (
	"fmt"
	"sort"
	"time"
)

// Finding is a rule's evidence-backed conclusion about a security-relevant
// configuration.
//
// A finding must be independently understandable: it identifies the affected
// resource, references every observation it relies on, explains the technical
// reasoning, states its limits and proposes remediation relative to the
// observed state.
type Finding struct {
	ID           string      `json:"id"`
	RuleID       string      `json:"rule_id"`
	RuleVersion  string      `json:"rule_version"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	Category     string      `json:"category"`
	Severity     Severity    `json:"severity"`
	Confidence   Confidence  `json:"confidence"`
	Resource     string      `json:"resource"`
	ResourceKind string      `json:"resource_kind"`
	Evidence     []string    `json:"evidence"`
	Explanation  string      `json:"explanation"`
	Impact       string      `json:"impact"`
	Remediation  string      `json:"remediation"`
	Limitations  []string    `json:"limitations,omitempty"`
	References   []Reference `json:"references,omitempty"`
	DetectedAt   time.Time   `json:"detected_at"`
}

// NewFinding constructs a finding with a deterministic ID derived from the
// rule, the affected resource and the stable title. Dynamic details belong in
// Explanation, never in Title, so IDs stay reproducible.
func NewFinding(meta RuleMetadata, resource, resourceKind string, severity Severity, confidence Confidence, title string, detectedAt time.Time) Finding {
	return Finding{
		ID:           stableID("fnd", meta.ID, resource, title),
		RuleID:       meta.ID,
		RuleVersion:  meta.Version,
		Title:        title,
		Description:  meta.Description,
		Category:     meta.Category,
		Severity:     severity,
		Confidence:   confidence,
		Resource:     resource,
		ResourceKind: resourceKind,
		DetectedAt:   detectedAt.UTC(),
	}
}

// AddEvidence attaches evidence references, guarding against duplicates.
func (f *Finding) AddEvidence(ids ...string) {
	seen := make(map[string]struct{}, len(f.Evidence)+len(ids))
	for _, id := range f.Evidence {
		seen[id] = struct{}{}
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		f.Evidence = append(f.Evidence, id)
	}
}

// Validate checks the structural invariants every finding must satisfy.
func (f Finding) Validate() error {
	switch {
	case f.ID == "":
		return fmt.Errorf("finding has no ID")
	case f.RuleID == "":
		return fmt.Errorf("finding %s has no rule ID", f.ID)
	case f.Title == "":
		return fmt.Errorf("finding %s has no title", f.ID)
	case f.Resource == "":
		return fmt.Errorf("finding %s has no resource", f.ID)
	case !f.Severity.Valid():
		return fmt.Errorf("finding %s has invalid severity %q", f.ID, f.Severity)
	case !f.Confidence.Valid():
		return fmt.Errorf("finding %s has invalid confidence %q", f.ID, f.Confidence)
	case len(f.Evidence) == 0:
		return fmt.Errorf("finding %s cites no evidence", f.ID)
	case f.Explanation == "":
		return fmt.Errorf("finding %s has no technical explanation", f.ID)
	}
	return nil
}

// SortFindings orders findings deterministically: severity descending, then
// rule ID, resource, title and ID ascending.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.ID < b.ID
	})
}

// RuleMetadata describes a detection rule. Metadata is exposed by
// `nulq rules list` and stored in the JSON schema, so it is part of the
// public contract.
type RuleMetadata struct {
	ID          string     `json:"id"`
	Version     string     `json:"version"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	Module      string     `json:"module"`
	Severity    Severity   `json:"default_severity"`
	Confidence  Confidence `json:"default_confidence"`
	Required    []Kind     `json:"required_observations"`
	Platforms   []string   `json:"platforms"`
}

// Validate checks that metadata is complete enough to be published.
func (m RuleMetadata) Validate() error {
	switch {
	case m.ID == "":
		return fmt.Errorf("rule metadata has no ID")
	case m.Version == "":
		return fmt.Errorf("rule %s has no version", m.ID)
	case m.Name == "":
		return fmt.Errorf("rule %s has no name", m.ID)
	case m.Description == "":
		return fmt.Errorf("rule %s has no description", m.ID)
	case m.Category == "":
		return fmt.Errorf("rule %s has no category", m.ID)
	case m.Module == "":
		return fmt.Errorf("rule %s has no module", m.ID)
	case !m.Severity.Valid():
		return fmt.Errorf("rule %s has invalid severity %q", m.ID, m.Severity)
	case !m.Confidence.Valid():
		return fmt.Errorf("rule %s has invalid confidence %q", m.ID, m.Confidence)
	case len(m.Required) == 0:
		return fmt.Errorf("rule %s declares no required observations", m.ID)
	case len(m.Platforms) == 0:
		return fmt.Errorf("rule %s declares no platforms", m.ID)
	}
	return nil
}

// RuleResult is what a rule returns to the engine.
type RuleResult struct {
	Findings []Finding  `json:"findings"`
	Evidence []Evidence `json:"evidence"`
}
