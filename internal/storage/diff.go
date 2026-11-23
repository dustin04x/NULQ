package storage

import (
	"fmt"
	"sort"

	"github.com/dustin04x/nulq/internal/core/models"
)

type FindingState string

const (
	StateNew        FindingState = "new"
	StateResolved   FindingState = "resolved"
	StateUnchanged  FindingState = "unchanged"
	StateChanged    FindingState = "changed"
	StateUnresolved FindingState = "unresolved"
)

type FindingDiff struct {
	ID              string       `json:"id"`
	RuleID          string       `json:"rule_id"`
	Resource        string       `json:"resource"`
	State           FindingState `json:"state"`
	SeverityOld     string       `json:"severity_old,omitempty"`
	SeverityNew     string       `json:"severity_new,omitempty"`
	ConfidenceOld   string       `json:"confidence_old,omitempty"`
	ConfidenceNew   string       `json:"confidence_new,omitempty"`
	EvidenceChanged bool         `json:"evidence_changed,omitempty"`
}

type ReportDiff struct {
	BaselineReportID string        `json:"baseline_report_id"`
	CurrentReportID  string        `json:"current_report_id"`
	New              []FindingDiff `json:"new"`
	Resolved         []FindingDiff `json:"resolved"`
	Unchanged        []FindingDiff `json:"unchanged"`
	Changed          []FindingDiff `json:"changed"`
	Unresolved       []FindingDiff `json:"unresolved,omitempty"`
	Warnings         []string      `json:"warnings,omitempty"`
}

func findingKey(f models.Finding) string {
	return f.RuleID + "\x00" + f.Resource
}

func CompareReports(baseline, current models.Report) ReportDiff {
	diff := ReportDiff{
		BaselineReportID: baseline.Scan.ReportID,
		CurrentReportID:  current.Scan.ReportID,
	}
	// warnings
	if baseline.Scan.Modules != nil && current.Scan.Modules != nil {
		if !sameStrings(baseline.Scan.Modules, current.Scan.Modules) {
			diff.Warnings = append(diff.Warnings, "module sets differ between reports")
		}
	}
	if baseline.Coverage.Status != current.Coverage.Status {
		diff.Warnings = append(diff.Warnings, fmt.Sprintf("coverage status differs: baseline=%s current=%s", baseline.Coverage.Status, current.Coverage.Status))
	}
	if baseline.Coverage.Status != models.CoverageComplete || current.Coverage.Status != models.CoverageComplete {
		diff.Warnings = append(diff.Warnings, "one or both scans are not coverage-complete; resolved findings may be inconclusive")
	}
	if baseline.Tool.Version != current.Tool.Version {
		diff.Warnings = append(diff.Warnings, fmt.Sprintf("scanner version differs: baseline=%s current=%s", baseline.Tool.Version, current.Tool.Version))
	}

	baseMap := map[string]models.Finding{}
	for _, f := range baseline.Findings {
		baseMap[findingKey(f)] = f
	}
	curMap := map[string]models.Finding{}
	for _, f := range current.Findings {
		curMap[findingKey(f)] = f
	}

	var keys []string
	for k := range baseMap {
		keys = append(keys, k)
	}
	for k := range curMap {
		if _, ok := baseMap[k]; !ok {
			keys = append(keys, k)
		}
	}
	// dedupe
	seen := map[string]bool{}
	var uniq []string
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, k)
	}
	sort.Strings(uniq)

	for _, k := range uniq {
		bf, inBase := baseMap[k]
		cf, inCur := curMap[k]
		ruleID, resource := splitKey(k)
		if inBase && !inCur {
			if current.Coverage.Status != models.CoverageComplete || !sameStrings(baseline.Scan.Modules, current.Scan.Modules) {
				diff.Warnings = append(diff.Warnings, fmt.Sprintf("finding %s may be unresolved due to incomplete coverage or module mismatch", bf.ID))
				diff.Unresolved = append(diff.Unresolved, FindingDiff{ID: bf.ID, RuleID: ruleID, Resource: resource, State: StateUnresolved, SeverityOld: string(bf.Severity), ConfidenceOld: string(bf.Confidence)})
				continue
			}
			diff.Resolved = append(diff.Resolved, FindingDiff{ID: bf.ID, RuleID: ruleID, Resource: resource, State: StateResolved, SeverityOld: string(bf.Severity), ConfidenceOld: string(bf.Confidence)})
			continue
		}
		if !inBase && inCur {
			diff.New = append(diff.New, FindingDiff{ID: cf.ID, RuleID: ruleID, Resource: resource, State: StateNew, SeverityNew: string(cf.Severity), ConfidenceNew: string(cf.Confidence)})
			continue
		}
		// both
		fd := FindingDiff{ID: cf.ID, RuleID: ruleID, Resource: resource, State: StateUnchanged, SeverityOld: string(bf.Severity), SeverityNew: string(cf.Severity), ConfidenceOld: string(bf.Confidence), ConfidenceNew: string(cf.Confidence)}
		changed := false
		if bf.Severity != cf.Severity {
			changed = true
		}
		if bf.Confidence != cf.Confidence {
			changed = true
		}
		if !sameStrings(bf.Evidence, cf.Evidence) {
			changed = true
			fd.EvidenceChanged = true
		}
		if changed {
			fd.State = StateChanged
			diff.Changed = append(diff.Changed, fd)
		} else {
			diff.Unchanged = append(diff.Unchanged, fd)
		}
	}
	return diff
}

func splitKey(k string) (string, string) {
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
