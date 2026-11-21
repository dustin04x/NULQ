// Package aggregation merges and orders rule output.
//
// Aggregation is the only place where findings from different rules meet. It
// enforces referential integrity between findings and evidence, removes exact
// duplicates and produces deterministic ordering, so identical system state
// yields byte-identical reports.
package aggregation

import (
	"fmt"
	"sort"

	"github.com/dustin04x/nulq/internal/core/models"
)

// Merge combines findings and evidence, validating that every referenced
// evidence ID is present. Duplicate findings (same stable ID) are merged by
// unioning their evidence references.
func Merge(findings []models.Finding, evidence []models.Evidence) ([]models.Finding, []models.Evidence, error) {
	evidenceByID := make(map[string]models.Evidence, len(evidence))
	uniqueEvidence := make([]models.Evidence, 0, len(evidence))
	for _, item := range evidence {
		if item.ID == "" {
			return nil, nil, fmt.Errorf("aggregation: evidence without ID for observation %q", item.ObservationID)
		}
		if _, ok := evidenceByID[item.ID]; ok {
			continue
		}
		evidenceByID[item.ID] = item
		uniqueEvidence = append(uniqueEvidence, item)
	}

	merged := make(map[string]models.Finding, len(findings))
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		if err := finding.Validate(); err != nil {
			return nil, nil, fmt.Errorf("aggregation: %w", err)
		}
		for _, evidenceID := range finding.Evidence {
			if _, ok := evidenceByID[evidenceID]; !ok {
				return nil, nil, fmt.Errorf(
					"aggregation: finding %s (%s) cites unknown evidence %s",
					finding.ID, finding.RuleID, evidenceID)
			}
		}
		if existing, ok := merged[finding.ID]; ok {
			existing.AddEvidence(finding.Evidence...)
			merged[finding.ID] = existing
			continue
		}
		merged[finding.ID] = finding
		order = append(order, finding.ID)
	}

	out := make([]models.Finding, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	models.SortFindings(out)
	sort.SliceStable(uniqueEvidence, func(i, j int) bool {
		return uniqueEvidence[i].ID < uniqueEvidence[j].ID
	})
	return out, uniqueEvidence, nil
}
