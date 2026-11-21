// Package api exposes NULQ's report contract to external programs.
//
// External tools should decode reports through this package instead of
// parsing terminal output. The types are aliases of the internal model, so a
// consumer sees exactly what the binary emits.
package api

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/dustin04x/nulq/internal/core/models"
)

// SchemaVersion is the report schema this build emits.
const SchemaVersion = models.SchemaVersion

// Report types.
type (
	Report       = models.Report
	Finding      = models.Finding
	Evidence     = models.Evidence
	Observation  = models.Observation
	ScanInfo     = models.ScanInfo
	HostInfo     = models.HostInfo
	ToolInfo     = models.ToolInfo
	Stats        = models.Stats
	Coverage     = models.Coverage
	RootCoverage = models.RootCoverage
	RuleInfo     = models.RuleMetadata
	Severity     = models.Severity
	Confidence   = models.Confidence
	Reference    = models.Reference
)

// Severities.
const (
	SeverityInfo     = models.SeverityInfo
	SeverityLow      = models.SeverityLow
	SeverityMedium   = models.SeverityMedium
	SeverityHigh     = models.SeverityHigh
	SeverityCritical = models.SeverityCritical
)

// Confidence levels.
const (
	ConfidenceLow    = models.ConfidenceLow
	ConfidenceMedium = models.ConfidenceMedium
	ConfidenceHigh   = models.ConfidenceHigh
)

// ParseReport decodes one JSON report. It accepts unknown fields so a newer
// producer remains consumable by an older client.
func ParseReport(r io.Reader) (Report, error) {
	var report Report
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("parse nulq report: %w", err)
	}
	return report, nil
}
