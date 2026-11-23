package reporting

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/dustin04x/nulq/internal/core/models"
)

// RenderSARIF writes a SARIF 2.1.0 document derived from report to w.
func RenderSARIF(w io.Writer, report models.Report) error {
	doc := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           report.Tool.Name,
					Version:        report.Tool.Version,
					InformationURI: "https://github.com/dustin04x/nulq",
					Rules:          sarifRules(report),
				},
			},
			Results: sarifResults(report),
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("render sarif: %w", err)
	}
	return nil
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifRules(report models.Report) []sarifRule {
	seen := map[string]struct{}{}
	var rules []sarifRule
	for _, f := range report.Findings {
		if _, ok := seen[f.RuleID]; ok {
			continue
		}
		seen[f.RuleID] = struct{}{}
		r := sarifRule{ID: f.RuleID}
		r.Name = f.RuleID
		r.ShortDescription.Text = f.Title
		r.FullDescription.Text = f.Description
		r.Help.Text = f.Remediation
		r.DefaultConfiguration.Level = sarifLevel(f.Severity)
		r.Properties = map[string]any{"version": f.RuleVersion, "category": f.Category}
		rules = append(rules, r)
	}
	return rules
}

func sarifResults(report models.Report) []sarifResult {
	results := []sarifResult{}
	for _, f := range report.Findings {
		res := sarifResult{RuleID: f.RuleID, Level: sarifLevel(f.Severity)}
		res.Message.Text = f.Explanation
		if f.Resource != "" {
			loc := sarifLocation{}
			loc.PhysicalLocation.ArtifactLocation.URI = f.Resource
			res.Locations = []sarifLocation{loc}
		}
		res.Fingerprints = map[string]string{"nulq/v1": f.ID}
		res.Properties = map[string]any{
			"confidence":  f.Confidence,
			"evidence":    f.Evidence,
			"limitations": f.Limitations,
		}
		results = append(results, res)
	}
	return results
}
