package reporting

import (
	"encoding/json"
	"io"

	"github.com/dustin04x/nulq/internal/core/models"
)

// JSON writes the report as a single indented document.
func JSON(w io.Writer, rep models.Report) error {
	rep.Normalize()
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(rep)
}

type jsonlHeader struct {
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	Tool          models.ToolInfo `json:"tool"`
	Host          models.HostInfo `json:"host"`
	Scan          models.ScanInfo `json:"scan"`
}

type jsonlFinding struct {
	Type string `json:"type"`
	models.Finding
}

type jsonlEvidence struct {
	Type string `json:"type"`
	models.Evidence
}

type jsonlObservation struct {
	Type string `json:"type"`
	models.Observation
}

type jsonlSummary struct {
	Type        string       `json:"type"`
	Stats       models.Stats `json:"stats"`
	Limitations []string     `json:"limitations"`
}

// JSONL writes newline-delimited JSON: one self-describing object per line.
// Every line is independently parseable, which makes streaming consumers and
// large reports practical.
func JSONL(w io.Writer, rep models.Report) error {
	rep.Normalize()
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	write := func(value any) error { return encoder.Encode(value) }

	if err := write(jsonlHeader{
		Type:          "scan",
		SchemaVersion: rep.SchemaVersion,
		Tool:          rep.Tool,
		Host:          rep.Host,
		Scan:          rep.Scan,
	}); err != nil {
		return err
	}
	for _, finding := range rep.Findings {
		if err := write(jsonlFinding{Type: "finding", Finding: finding}); err != nil {
			return err
		}
	}
	for _, item := range rep.Evidence {
		if err := write(jsonlEvidence{Type: "evidence", Evidence: item}); err != nil {
			return err
		}
	}
	for _, observation := range rep.Observations {
		if err := write(jsonlObservation{Type: "observation", Observation: observation}); err != nil {
			return err
		}
	}
	return write(jsonlSummary{Type: "summary", Stats: rep.Stats, Limitations: rep.Limitations})
}
