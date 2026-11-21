package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// Manifest is the scenario contract for one laboratory target.
type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Target        string `json:"target"`
	Description   string `json:"description,omitempty"`
	// Artifacts maps a scan key used by scenarios to a report filename in the
	// results directory.
	Artifacts map[string]string `json:"artifacts"`
	Scenarios []Scenario        `json:"scenarios"`
}

// Scenario is one verifiable expectation about a laboratory scan.
type Scenario struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Environment string `json:"environment"` // live, synthetic or unsupported
	Supported   bool   `json:"supported"`
	// Reason explains why a scenario is not supported yet. Required when
	// supported is false so an unimplemented check can never look like a pass.
	Reason      string `json:"reason,omitempty"`
	Description string `json:"description,omitempty"`
	// Scan names the artifact this scenario evaluates. Empty for unsupported
	// scenarios.
	Scan string `json:"scan,omitempty"`
	// Scope restricts unexpected-finding analysis to these resource prefixes.
	// Empty disables unexpected analysis for the scenario.
	Scope  []string     `json:"scope,omitempty"`
	Expect Expectations `json:"expect,omitempty"`
}

// Expectations is the complete set of assertions for a scenario.
type Expectations struct {
	Findings       []FindingExpectation `json:"findings,omitempty"`
	AbsentFindings []FindingExpectation `json:"absent_findings,omitempty"`
	// AllowedFindings accounts for findings that are expected but deliberately
	// not asserted, for example kernel-dependent sysctls. Anything neither
	// asserted nor allowed is an unaccounted finding and fails the run.
	AllowedFindings []FindingExpectation     `json:"allowed_findings,omitempty"`
	Observations    []ObservationExpectation `json:"observations,omitempty"`
	Coverage        *CoverageExpectation     `json:"coverage,omitempty"`
	Report          *ReportExpectation       `json:"report,omitempty"`
	MaxSeverity     string                   `json:"max_severity,omitempty"`
}

// FindingExpectation selects findings by rule and resource.
type FindingExpectation struct {
	RuleID     string `json:"rule_id,omitempty"`
	Resource   string `json:"resource,omitempty"`
	Match      string `json:"match,omitempty"` // exact, prefix, glob or any
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Min        *int   `json:"min,omitempty"`
	Max        *int   `json:"max,omitempty"`
}

// MinCount returns the required number of matches, defaulting to one.
func (e FindingExpectation) MinCount() int {
	if e.Min != nil {
		return *e.Min
	}
	return 1
}

// MaxCount returns the permitted number of matches, defaulting to MinCount so
// an expectation without bounds asserts an exact count.
func (e FindingExpectation) MaxCount() int {
	if e.Max != nil {
		return *e.Max
	}
	return e.MinCount()
}

// ObservationExpectation selects observations by kind, resource and attribute.
type ObservationExpectation struct {
	Kind     string `json:"kind"`
	Resource string `json:"resource,omitempty"`
	Status   string `json:"status,omitempty"`
	Attr     string `json:"attr,omitempty"`
	Equals   string `json:"equals,omitempty"`
	Min      *int   `json:"min,omitempty"`
}

// MinCount returns the required number of matches, defaulting to one.
func (e ObservationExpectation) MinCount() int {
	if e.Min != nil {
		return *e.Min
	}
	return 1
}

// CoverageExpectation asserts published coverage facts.
type CoverageExpectation struct {
	Status               string   `json:"status,omitempty"`
	Complete             *bool    `json:"complete,omitempty"`
	ExecutionComplete    *bool    `json:"execution_complete,omitempty"`
	PermissionDeniedMin  *int     `json:"permission_denied_min,omitempty"`
	ExcludedRootsInclude []string `json:"excluded_roots_include,omitempty"`
}

// ReportExpectation asserts scan-level metadata.
type ReportExpectation struct {
	Unprivileged *bool    `json:"unprivileged,omitempty"`
	IncludeRoots []string `json:"include_roots,omitempty"`
	ExcludeRoots []string `json:"exclude_roots,omitempty"`
}

// LoadManifest reads and validates a manifest file.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate rejects manifests that could hide a gap: duplicate IDs, unknown
// scans, missing reasons for unsupported scenarios and invalid match modes.
func (m Manifest) Validate() error {
	if m.SchemaVersion != "1.0" {
		return fmt.Errorf("manifest schema_version = %q, want 1.0", m.SchemaVersion)
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("manifest declares no artifacts")
	}
	if len(m.Scenarios) == 0 {
		return fmt.Errorf("manifest declares no scenarios")
	}

	seen := make(map[string]struct{}, len(m.Scenarios))
	for _, scenario := range m.Scenarios {
		if scenario.ID == "" {
			return fmt.Errorf("scenario without an ID")
		}
		if _, duplicate := seen[scenario.ID]; duplicate {
			return fmt.Errorf("duplicate scenario ID %q", scenario.ID)
		}
		seen[scenario.ID] = struct{}{}
		if scenario.Title == "" || scenario.Category == "" {
			return fmt.Errorf("scenario %s needs a title and category", scenario.ID)
		}
		switch scenario.Environment {
		case "live", "synthetic", "unsupported":
		default:
			return fmt.Errorf("scenario %s has unknown environment %q", scenario.ID, scenario.Environment)
		}
		if !scenario.Supported {
			if strings.TrimSpace(scenario.Reason) == "" {
				return fmt.Errorf("unsupported scenario %s must state a reason", scenario.ID)
			}
			if len(scenario.Expect.Findings) > 0 || len(scenario.Expect.Observations) > 0 {
				return fmt.Errorf("unsupported scenario %s must not declare expectations", scenario.ID)
			}
			continue
		}
		if _, ok := m.Artifacts[scenario.Scan]; !ok {
			return fmt.Errorf("scenario %s references unknown scan %q", scenario.ID, scenario.Scan)
		}
		if len(scenario.Expect.Findings)+len(scenario.Expect.AbsentFindings)+
			len(scenario.Expect.Observations) == 0 &&
			scenario.Expect.Coverage == nil && scenario.Expect.Report == nil &&
			scenario.Expect.MaxSeverity == "" {
			return fmt.Errorf("scenario %s declares no expectations", scenario.ID)
		}
		for _, expectation := range append(append(append([]FindingExpectation{}, scenario.Expect.Findings...), scenario.Expect.AbsentFindings...), scenario.Expect.AllowedFindings...) {
			switch expectation.Match {
			case "", "exact", "prefix", "glob", "any":
			default:
				return fmt.Errorf("scenario %s uses unknown match mode %q", scenario.ID, expectation.Match)
			}
			if _, err := path.Match(patternOrDefault(expectation), ""); err != nil {
				return fmt.Errorf("scenario %s has invalid glob %q", scenario.ID, expectation.Resource)
			}
		}
	}
	return nil
}

// ScanNames returns the artifact keys in deterministic order.
func (m Manifest) ScanNames() []string {
	names := make([]string, 0, len(m.Artifacts))
	for name := range m.Artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func patternOrDefault(expectation FindingExpectation) string {
	if expectation.Resource == "" {
		return "*"
	}
	return expectation.Resource
}
