package aggregation

import (
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

func testMetadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID: "NULQ-T-001", Version: "1.0.0", Name: "Test", Description: "desc",
		Category: "test", Module: "test", Severity: models.SeverityLow,
		Confidence: models.ConfidenceHigh, Required: []models.Kind{models.KindFile},
		Platforms: []string{"linux"},
	}
}

func testFinding(resource string, severity models.Severity, evidenceID string) models.Finding {
	finding := models.NewFinding(testMetadata(), resource, models.ResourceFile, severity, models.ConfidenceHigh, "Test", time.Now())
	finding.Explanation = "because"
	finding.AddEvidence(evidenceID)
	return finding
}

func testEvidence(observationID string) models.Evidence {
	return models.Evidence{
		ID: models.EvidenceID(observationID, "mode"), ObservationID: observationID,
		Resource: "/x", Collector: "test", Field: "mode", ObservedValue: "0755",
		Explanation: "observed", CollectedAt: time.Now(),
	}
}

func TestMergeRejectsDanglingEvidence(t *testing.T) {
	finding := testFinding("/x", models.SeverityHigh, "ev-000000000000")
	if _, _, err := Merge([]models.Finding{finding}, nil); err == nil {
		t.Fatal("a finding citing unknown evidence must be rejected")
	}
}

func TestMergeDeduplicatesAndOrders(t *testing.T) {
	highEvidence := testEvidence("obs-high")
	lowEvidence := testEvidence("obs-low")
	high := testFinding("/high", models.SeverityHigh, highEvidence.ID)
	low := testFinding("/low", models.SeverityLow, lowEvidence.ID)

	findings, evidence, err := Merge(
		[]models.Finding{low, high, high},
		[]models.Evidence{lowEvidence, highEvidence, highEvidence},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 unique findings, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Fatalf("HIGH must sort first, got %s", findings[0].Severity)
	}
	if len(evidence) != 2 {
		t.Fatalf("want 2 unique evidence items, got %d", len(evidence))
	}
	if evidence[0].ID > evidence[1].ID {
		t.Fatal("evidence must be sorted by ID")
	}
}
