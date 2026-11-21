package models

import "time"

// Evidence is a single observed fact that supports a finding.
//
// Evidence exists so a reviewer can trace a conclusion back to the original
// observation without re-running the scan. Evidence never contains secrets;
// collectors are responsible for redaction before an observation is
// published.
type Evidence struct {
	ID            string    `json:"id"`
	ObservationID string    `json:"observation_id"`
	Resource      string    `json:"resource"`
	ResourceKind  string    `json:"resource_kind,omitempty"`
	Collector     string    `json:"collector"`
	Field         string    `json:"field,omitempty"`
	ObservedValue string    `json:"observed_value"`
	ExpectedValue string    `json:"expected_value,omitempty"`
	Explanation   string    `json:"explanation"`
	CollectedAt   time.Time `json:"collected_at"`
}

// EvidenceID derives a stable identifier for an evidence item. The ID is a
// function of the observation and the field it cites, which makes duplicate
// evidence references collapse naturally.
func EvidenceID(observationID, field string) string {
	return stableID("ev", observationID, field)
}

// Reference is an external source supporting a finding.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
