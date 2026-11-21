package models

import (
	"io/fs"
	"testing"
	"time"
)

func TestSeverityRankingAndParsing(t *testing.T) {
	if SeverityHigh.Rank() <= SeverityMedium.Rank() {
		t.Fatal("HIGH must rank above MEDIUM")
	}
	parsed, err := ParseSeverity(" medium ")
	if err != nil || parsed != SeverityMedium {
		t.Fatalf("ParseSeverity: got %q, %v", parsed, err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected an error for an unknown severity")
	}
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Fatal("CRITICAL must satisfy a HIGH threshold")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Fatal("LOW must not satisfy a HIGH threshold")
	}
	if Severity("").AtLeast(SeverityInfo) {
		t.Fatal("an empty severity must never satisfy a threshold")
	}
}

func TestModeFormatting(t *testing.T) {
	mode := fs.FileMode(0o755) | fs.ModeSetuid | fs.ModeSticky
	if got := ModeOctal(mode); got != "5755" {
		t.Fatalf("ModeOctal = %q, want 5755", got)
	}
	if got := ModeSymbolic(mode); got != "rwsr-xr-t" {
		t.Fatalf("ModeSymbolic = %q, want rwsr-xr-t", got)
	}
	if got := ModeOctal(fs.FileMode(0o644)); got != "0644" {
		t.Fatalf("ModeOctal = %q, want 0644", got)
	}
}

func TestObservationIDsAreStableAndKindScoped(t *testing.T) {
	observedAt := time.Now()
	first := NewObservation(KindFile, "/usr/bin/passwd", "collector-a", observedAt, map[string]string{AttrMode: "4755"})
	second := NewObservation(KindFile, "/usr/bin/passwd", "collector-b", observedAt.Add(time.Hour), map[string]string{AttrMode: "0755"})

	if first.ID != second.ID {
		t.Fatalf("IDs must not depend on collector or time: %q != %q", first.ID, second.ID)
	}
	if ObservationID(KindFile, "/usr/bin/passwd") == ObservationID(KindDirectory, "/usr/bin/passwd") {
		t.Fatal("IDs must be scoped by kind")
	}
	if !first.CollectedAt.Equal(observedAt.UTC()) {
		t.Fatal("collected_at must be normalised to UTC")
	}
}

func TestObservationCopiesAttributes(t *testing.T) {
	attributes := map[string]string{AttrMode: "0755"}
	obs := NewObservation(KindFile, "/tmp/f", "test", time.Now(), attributes)
	attributes[AttrMode] = "0777"
	if got, _ := obs.Attr(AttrMode); got != "0755" {
		t.Fatalf("observation attributes must be copied, got %q", got)
	}

	clone := obs.Clone()
	clone.Set(AttrMode, "0700")
	if original, _ := obs.Attr(AttrMode); original != "0755" {
		t.Fatal("Clone must deep-copy attributes")
	}
}

func TestFindingValidationAndStableIDs(t *testing.T) {
	meta := RuleMetadata{
		ID:          "NULQ-T-001",
		Version:     "1.0.0",
		Name:        "Test rule",
		Description: "Test description",
		Category:    "test",
		Module:      "test",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Required:    []Kind{KindFile},
		Platforms:   []string{"linux"},
	}
	if err := meta.Validate(); err != nil {
		t.Fatalf("metadata should be valid: %v", err)
	}

	finding := NewFinding(meta, "/tmp/example", ResourceFile, SeverityMedium, ConfidenceHigh, "Example", time.Now())
	if err := finding.Validate(); err == nil {
		t.Fatal("a finding without evidence must be rejected")
	}

	finding.Explanation = "Observed fact with consequences."
	finding.AddEvidence("ev-000000000000", "ev-000000000000")
	if err := finding.Validate(); err != nil {
		t.Fatalf("finding should be valid: %v", err)
	}
	if len(finding.Evidence) != 1 {
		t.Fatalf("duplicate evidence references must collapse, got %v", finding.Evidence)
	}

	repeat := NewFinding(meta, "/tmp/example", ResourceFile, SeverityMedium, ConfidenceHigh, "Example", time.Now())
	if repeat.ID != finding.ID {
		t.Fatal("finding IDs must be deterministic")
	}
	if other := NewFinding(meta, "/tmp/other", ResourceFile, SeverityMedium, ConfidenceHigh, "Example", time.Now()); other.ID == finding.ID {
		t.Fatal("different resources must produce different finding IDs")
	}
}

func TestSortFindingsBySeverityThenIdentity(t *testing.T) {
	meta := RuleMetadata{
		ID: "NULQ-T-002", Version: "1", Name: "n", Description: "d", Category: "c",
		Module: "m", Severity: SeverityInfo, Confidence: ConfidenceHigh,
		Required: []Kind{KindFile}, Platforms: []string{"linux"},
	}
	makeFinding := func(severity Severity, resource string) Finding {
		f := NewFinding(meta, resource, ResourceFile, severity, ConfidenceHigh, "t", time.Now())
		f.Explanation = "e"
		f.AddEvidence("ev-x")
		return f
	}
	findings := []Finding{
		makeFinding(SeverityLow, "/b"),
		makeFinding(SeverityHigh, "/z"),
		makeFinding(SeverityHigh, "/a"),
	}
	SortFindings(findings)

	if findings[0].Severity != SeverityHigh || findings[1].Severity != SeverityHigh {
		t.Fatalf("HIGH findings must sort first: %+v", findings)
	}
	if findings[0].Resource != "/a" || findings[1].Resource != "/z" {
		t.Fatalf("findings with equal severity must sort by resource: %+v", findings)
	}
}
