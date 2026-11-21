package lab

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

// ScanArtifact is one loaded report plus its schema verdict.
type ScanArtifact struct {
	Name         string
	Artifact     string
	Report       models.Report
	Loaded       bool
	SchemaErrors []string
}

// Valid reports whether the artifact was loaded and conforms to the schema.
func (a ScanArtifact) Valid() bool { return a.Loaded && len(a.SchemaErrors) == 0 }

// Isolation is the container's self-reported security state.
type Isolation struct {
	UID                   int    `json:"uid"`
	NonRoot               bool   `json:"non_root"`
	ReadOnlyRoot          bool   `json:"read_only_root"`
	EffectiveCapabilities string `json:"effective_capabilities"`
	CapabilitiesDropped   bool   `json:"capabilities_dropped"`
	NoNewPrivileges       bool   `json:"no_new_privileges"`
	NetworkInterfaces     string `json:"network_interfaces"`
	NetworkProbe          string `json:"network_probe"`
	NetworkIsolated       bool   `json:"network_isolated"`
	DockerSocketPresent   bool   `json:"docker_socket_present"`
	NulqExecutable        bool   `json:"nulq_executable"`
	TmpWritable           bool   `json:"tmp_writable"`
	TmpNoExec             bool   `json:"tmp_noexec"`
}

// ImageInfo describes the exact laboratory image that was exercised.
type ImageInfo struct {
	Image       string `json:"image"`
	ImageID     string `json:"image_id"`
	BaseImage   string `json:"base_image"`
	BaseDigest  string `json:"base_digest"`
	NulqVersion string `json:"nulq_version"`
	BuiltAt     string `json:"built_at"`
}

// Environment records what the laboratory actually used.
type Environment struct {
	Target       string `json:"target"`
	Image        string `json:"image,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	BaseImage    string `json:"base_image,omitempty"`
	BaseDigest   string `json:"base_digest,omitempty"`
	NulqVersion  string `json:"nulq_version,omitempty"`
	BuiltAt      string `json:"built_at,omitempty"`
	ContainerUID int    `json:"container_uid,omitempty"`
}

// Check is one pass/fail assertion with its evidence.
type Check struct {
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail,omitempty"`
}

// IsolationReport records the probe result and the assertions made from it.
type IsolationReport struct {
	Probe  Isolation `json:"probe"`
	Checks []Check   `json:"checks"`
	Passed bool      `json:"passed"`
}

// Summary is the verdict-level accounting for a laboratory run.
type Summary struct {
	Passed                  bool `json:"passed"`
	ScenariosTotal          int  `json:"scenarios_total"`
	ScenariosPassed         int  `json:"scenarios_passed"`
	ScenariosFailed         int  `json:"scenarios_failed"`
	ScenariosUnsupported    int  `json:"scenarios_unsupported"`
	ExpectedFindings        int  `json:"expected_findings"`
	ActualFindings          int  `json:"actual_findings"`
	MissingFindings         int  `json:"missing_findings"`
	UnexpectedFindings      int  `json:"unexpected_findings"`
	SeverityMismatches      int  `json:"severity_mismatches"`
	ConfidenceMismatches    int  `json:"confidence_mismatches"`
	DuplicateFindings       int  `json:"duplicate_findings"`
	DanglingEvidence        int  `json:"dangling_evidence"`
	FindingsWithoutEvidence int  `json:"findings_without_evidence"`
	UnaccountedFindings     int  `json:"unaccounted_findings"`
	ScansValidated          int  `json:"scans_validated"`
	ScansInvalid            int  `json:"scans_invalid"`
}

// ScanSummary records one report's metadata and coverage.
type ScanSummary struct {
	Name          string          `json:"name"`
	Artifact      string          `json:"artifact"`
	ReportID      string          `json:"report_id"`
	Hostname      string          `json:"hostname"`
	OSID          string          `json:"os_id,omitempty"`
	SchemaVersion string          `json:"schema_version"`
	DurationMS    int64           `json:"duration_ms"`
	Findings      int             `json:"findings"`
	Observations  int             `json:"observations"`
	SchemaValid   bool            `json:"schema_valid"`
	SchemaErrors  []string        `json:"schema_errors,omitempty"`
	Coverage      models.Coverage `json:"coverage"`
}

// ScenarioResult is the verdict for one scenario.
type ScenarioResult struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Category    string  `json:"category"`
	Environment string  `json:"environment"`
	Scan        string  `json:"scan,omitempty"`
	Supported   bool    `json:"supported"`
	Status      string  `json:"status"` // passed, failed or unsupported
	Reason      string  `json:"reason,omitempty"`
	Findings    int     `json:"findings"`
	Checks      []Check `json:"checks"`
}

// FindingRef identifies a finding without duplicating its full text.
type FindingRef struct {
	Scenario string `json:"scenario"`
	RuleID   string `json:"rule_id"`
	Resource string `json:"resource"`
	Severity string `json:"severity"`
}

// Mismatch records a severity or confidence disagreement.
type Mismatch struct {
	Scenario string `json:"scenario"`
	RuleID   string `json:"rule_id"`
	Resource string `json:"resource"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// FindingTally counts findings per rule.
type FindingTally struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// FindingsReport is the expected-versus-actual finding comparison.
type FindingsReport struct {
	Total                int            `json:"total"`
	ByRule               []FindingTally `json:"by_rule"`
	Missing              []FindingRef   `json:"missing"`
	Unexpected           []FindingRef   `json:"unexpected"`
	Unaccounted          []FindingRef   `json:"unaccounted"`
	Duplicates           []FindingRef   `json:"duplicates"`
	SeverityMismatches   []Mismatch     `json:"severity_mismatches"`
	ConfidenceMismatches []Mismatch     `json:"confidence_mismatches"`
}

// ScanCoverage is the coverage of one scan artifact.
type ScanCoverage struct {
	Scan                string                    `json:"scan"`
	Status              string                    `json:"status"`
	ExecutionComplete   bool                      `json:"execution_complete"`
	CoverageComplete    bool                      `json:"coverage_complete"`
	FilesExamined       int                       `json:"files_examined"`
	DirectoriesExamined int                       `json:"directories_examined"`
	TraversalErrors     int                       `json:"traversal_errors"`
	PermissionDenied    int                       `json:"permission_denied"`
	TruncatedRoots      []string                  `json:"truncated_roots"`
	ExcludedRoots       []string                  `json:"excluded_roots"`
	FailedOperations    []models.OperationFailure `json:"failed_operations"`
}

// Result is the validation.json document.
type Result struct {
	SchemaVersion    string           `json:"schema_version"`
	GeneratedAt      string           `json:"generated_at"`
	Environment      Environment      `json:"environment"`
	Isolation        IsolationReport  `json:"isolation"`
	Summary          Summary          `json:"summary"`
	Scans            []ScanSummary    `json:"scans"`
	Scenarios        []ScenarioResult `json:"scenarios"`
	Findings         FindingsReport   `json:"findings"`
	Coverage         []ScanCoverage   `json:"coverage"`
	CollectionErrors []string         `json:"collection_errors"`
	Limitations      []string         `json:"limitations"`
}

// Limitations are repeated in every validation artifact so a reader cannot
// mistake fixture behaviour for host behaviour.
var Limitations = []string{
	"Fixture scans (--root /lab/fixtures) assess synthetic objects created at image build time; they are not live operating-system observations.",
	"Baseline scans mount an empty tmpfs over /lab/fixtures, so fixture findings can never appear as live Alpine observations.",
	"Alpine/BusyBox cannot represent systemd, PAM, SELinux or distribution package layout; those scenarios are reported as unsupported.",
	"The container shares the Docker host kernel; sysctl observations describe that kernel, not bare metal.",
	"Container isolation is proven by inspection and in-container checks, not by kernel auditing.",
}

// Evaluate produces the laboratory verdict. It never marks an unsupported
// scenario as passed, and a scenario only passes when every assertion holds.
func Evaluate(manifest Manifest, scans map[string]ScanArtifact, isolation Isolation, image ImageInfo) Result {
	result := Result{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Environment: Environment{
			Target:       manifest.Target,
			Image:        image.Image,
			ImageID:      image.ImageID,
			BaseImage:    image.BaseImage,
			BaseDigest:   image.BaseDigest,
			NulqVersion:  image.NulqVersion,
			BuiltAt:      image.BuiltAt,
			ContainerUID: isolation.UID,
		},
		Isolation:        verifyIsolation(isolation),
		Findings:         FindingsReport{ByRule: []FindingTally{}, Missing: []FindingRef{}, Unexpected: []FindingRef{}, Unaccounted: []FindingRef{}, Duplicates: []FindingRef{}, SeverityMismatches: []Mismatch{}, ConfidenceMismatches: []Mismatch{}},
		Coverage:         []ScanCoverage{},
		CollectionErrors: []string{},
		Limitations:      append([]string{}, Limitations...),
		Scenarios:        []ScenarioResult{},
		Scans:            []ScanSummary{},
	}

	for _, name := range manifest.ScanNames() {
		artifact := scans[name]
		summary := ScanSummary{
			Name:         name,
			Artifact:     artifact.Artifact,
			SchemaValid:  artifact.Valid(),
			SchemaErrors: artifact.SchemaErrors,
		}
		if artifact.Loaded {
			summary.ReportID = artifact.Report.Scan.ReportID
			summary.Hostname = artifact.Report.Host.Hostname
			summary.OSID = artifact.Report.Host.OSID
			summary.SchemaVersion = artifact.Report.SchemaVersion
			summary.DurationMS = artifact.Report.Scan.DurationMS
			summary.Findings = len(artifact.Report.Findings)
			summary.Observations = artifact.Report.Stats.Observations
			summary.Coverage = artifact.Report.Coverage
			result.Coverage = append(result.Coverage, ScanCoverage{
				Scan:                name,
				Status:              artifact.Report.Coverage.Status,
				ExecutionComplete:   artifact.Report.Coverage.ExecutionComplete,
				CoverageComplete:    artifact.Report.Coverage.CoverageComplete,
				FilesExamined:       artifact.Report.Coverage.FilesExamined,
				DirectoriesExamined: artifact.Report.Coverage.DirectoriesExamined,
				TraversalErrors:     artifact.Report.Coverage.TraversalErrors,
				PermissionDenied:    artifact.Report.Coverage.PermissionDenied,
				TruncatedRoots:      artifact.Report.Coverage.TruncatedRoots,
				ExcludedRoots:       artifact.Report.Coverage.ExcludedRoots,
				FailedOperations:    artifact.Report.Coverage.FailedOperations,
			})
			duplicates, dangling, withoutEvidence := auditIntegrity(artifact.Report)
			result.Findings.Duplicates = append(result.Findings.Duplicates, duplicates...)
			result.Summary.DuplicateFindings += len(duplicates)
			result.Summary.DanglingEvidence += dangling
			result.Summary.FindingsWithoutEvidence += withoutEvidence
			if dangling > 0 {
				result.CollectionErrors = append(result.CollectionErrors, fmt.Sprintf(
					"%s: %d finding(s) cite evidence IDs that are absent from the report", name, dangling))
			}
			if withoutEvidence > 0 {
				result.CollectionErrors = append(result.CollectionErrors, fmt.Sprintf(
					"%s: %d finding(s) cite no evidence at all", name, withoutEvidence))
			}
			result.Findings.Total += len(artifact.Report.Findings)
			result.CollectionErrors = append(result.CollectionErrors, collectionErrors(name, artifact.Report)...)
		}
		if artifact.Valid() {
			result.Summary.ScansValidated++
		} else {
			result.Summary.ScansInvalid++
		}
		result.Scans = append(result.Scans, summary)
	}

	tallies := map[string]int{}
	accountedByScan := map[string]map[string]struct{}{}
	for _, scenario := range manifest.Scenarios {
		outcome := evaluateScenario(scenario, scans[scenario.Scan])
		result.Scenarios = append(result.Scenarios, outcome.result)
		if scenario.Scan != "" {
			if accountedByScan[scenario.Scan] == nil {
				accountedByScan[scenario.Scan] = map[string]struct{}{}
			}
			for _, id := range outcome.accounted {
				accountedByScan[scenario.Scan][id] = struct{}{}
			}
		}
		result.Findings.Missing = append(result.Findings.Missing, outcome.missing...)
		result.Findings.Unexpected = append(result.Findings.Unexpected, outcome.unexpected...)
		result.Findings.SeverityMismatches = append(result.Findings.SeverityMismatches, outcome.severityMismatches...)
		result.Findings.ConfidenceMismatches = append(result.Findings.ConfidenceMismatches, outcome.confidenceMismatches...)
		result.Summary.ExpectedFindings += outcome.expectedFindings

		switch outcome.result.Status {
		case "passed":
			result.Summary.ScenariosPassed++
		case "failed":
			result.Summary.ScenariosFailed++
		case "unsupported":
			result.Summary.ScenariosUnsupported++
		}
	}
	result.Summary.ScenariosTotal = len(result.Scenarios)

	// Explicitly allowed findings are expected but not asserted (for example
	// kernel-dependent sysctls). They are accounted for per scan so the
	// unexpected counter means "not asserted and not allowed", not "outside a
	// scenario's convenience scope".
	for _, scenario := range manifest.Scenarios {
		if !scenario.Supported || scenario.Scan == "" || len(scenario.Expect.AllowedFindings) == 0 {
			continue
		}
		artifact := scans[scenario.Scan]
		if !artifact.Loaded || !artifact.Valid() {
			continue
		}
		if accountedByScan[scenario.Scan] == nil {
			accountedByScan[scenario.Scan] = map[string]struct{}{}
		}
		for _, allowed := range scenario.Expect.AllowedFindings {
			for _, finding := range matchFindings(artifact.Report.Findings, allowed) {
				accountedByScan[scenario.Scan][finding.ID] = struct{}{}
			}
		}
	}

	for _, name := range manifest.ScanNames() {
		artifact := scans[name]
		if !artifact.Loaded || !artifact.Valid() {
			continue
		}
		accounted := accountedByScan[name]
		for _, finding := range artifact.Report.Findings {
			if _, ok := accounted[finding.ID]; ok {
				continue
			}
			result.Findings.Unaccounted = append(result.Findings.Unaccounted, FindingRef{
				Scenario: "unaccounted:" + name, RuleID: finding.RuleID,
				Resource: finding.Resource, Severity: string(finding.Severity),
			})
		}
	}
	result.Summary.UnaccountedFindings = len(result.Findings.Unaccounted)

	counted := map[string]struct{}{}
	for _, scenario := range manifest.Scenarios {
		if _, done := counted[scenario.Scan]; done || scenario.Scan == "" {
			continue
		}
		counted[scenario.Scan] = struct{}{}
		for _, finding := range scans[scenario.Scan].Report.Findings {
			tallies[finding.RuleID]++
		}
	}
	for rule, count := range tallies {
		result.Findings.ByRule = append(result.Findings.ByRule, FindingTally{RuleID: rule, Count: count})
	}
	sort.Slice(result.Findings.ByRule, func(i, j int) bool { return result.Findings.ByRule[i].RuleID < result.Findings.ByRule[j].RuleID })

	result.Summary.ActualFindings = result.Findings.Total
	result.Summary.MissingFindings = len(result.Findings.Missing)
	result.Summary.UnexpectedFindings = len(result.Findings.Unexpected)
	result.Summary.SeverityMismatches = len(result.Findings.SeverityMismatches)
	result.Summary.ConfidenceMismatches = len(result.Findings.ConfidenceMismatches)
	result.Summary.Passed = result.Summary.ScenariosFailed == 0 &&
		result.Summary.ScansInvalid == 0 &&
		result.Summary.DuplicateFindings == 0 &&
		result.Summary.DanglingEvidence == 0 &&
		result.Summary.FindingsWithoutEvidence == 0 &&
		result.Summary.UnaccountedFindings == 0 &&
		result.Isolation.Passed
	if !result.Isolation.Passed {
		result.Limitations = append(result.Limitations, "Container isolation was not fully established; results must not be treated as sandboxed.")
	}
	return result
}

type scenarioOutcome struct {
	result               ScenarioResult
	expectedFindings     int
	accounted            []string
	missing              []FindingRef
	unexpected           []FindingRef
	severityMismatches   []Mismatch
	confidenceMismatches []Mismatch
}

func evaluateScenario(scenario Scenario, artifact ScanArtifact) scenarioOutcome {
	outcome := scenarioOutcome{result: ScenarioResult{
		ID:          scenario.ID,
		Title:       scenario.Title,
		Category:    scenario.Category,
		Environment: scenario.Environment,
		Scan:        scenario.Scan,
		Supported:   scenario.Supported,
		Checks:      []Check{},
	}}

	if !scenario.Supported {
		outcome.result.Status = "unsupported"
		outcome.result.Reason = scenario.Reason
		return outcome
	}

	fail := func(description, detail string) {
		outcome.result.Checks = append(outcome.result.Checks, Check{Description: description, Passed: false, Detail: detail})
		outcome.result.Status = "failed"
	}
	pass := func(description, detail string) {
		outcome.result.Checks = append(outcome.result.Checks, Check{Description: description, Passed: true, Detail: detail})
	}
	outcome.result.Status = "passed"

	if !artifact.Loaded {
		fail("scan artifact is present and readable", "no report loaded for "+scenario.Scan)
		return outcome
	}
	if !artifact.Valid() {
		fail("report conforms to the published schema", strings.Join(artifact.SchemaErrors, "; "))
		return outcome
	}

	matched := map[string]struct{}{}
	for _, expectation := range scenario.Expect.Findings {
		matches := matchFindings(artifact.Report.Findings, expectation)
		for _, finding := range matches {
			matched[finding.ID] = struct{}{}
			outcome.accounted = append(outcome.accounted, finding.ID)
		}
		minimum, maximum := expectation.MinCount(), expectation.MaxCount()
		outcome.expectedFindings += minimum
		description := describeExpectation(expectation)
		detail := fmt.Sprintf("matched %d, expected %d..%d", len(matches), minimum, maximum)
		if len(matches) < minimum {
			outcome.missing = append(outcome.missing, FindingRef{
				Scenario: scenario.ID,
				RuleID:   expectation.RuleID,
				Resource: expectation.Resource,
				Severity: expectation.Severity,
			})
		}
		if len(matches) < minimum || len(matches) > maximum {
			fail(description, detail)
		} else {
			pass(description, detail)
		}
		for _, finding := range matches {
			if expectation.Severity != "" && !strings.EqualFold(string(finding.Severity), expectation.Severity) {
				outcome.severityMismatches = append(outcome.severityMismatches, Mismatch{
					Scenario: scenario.ID, RuleID: finding.RuleID, Resource: finding.Resource,
					Expected: expectation.Severity, Actual: string(finding.Severity),
				})
				fail("severity for "+finding.Resource, "expected "+expectation.Severity+", got "+string(finding.Severity))
			}
			if expectation.Confidence != "" && !strings.EqualFold(string(finding.Confidence), expectation.Confidence) {
				outcome.confidenceMismatches = append(outcome.confidenceMismatches, Mismatch{
					Scenario: scenario.ID, RuleID: finding.RuleID, Resource: finding.Resource,
					Expected: expectation.Confidence, Actual: string(finding.Confidence),
				})
				fail("confidence for "+finding.Resource, "expected "+expectation.Confidence+", got "+string(finding.Confidence))
			}
		}
	}

	for _, expectation := range scenario.Expect.AbsentFindings {
		// Absence assertions honour a severity or confidence filter: "no HIGH
		// finding on this resource" must not match the MEDIUM finding that is
		// expected to exist.
		matches := matchFindingsStrict(artifact.Report.Findings, expectation)
		for _, finding := range matches {
			matched[finding.ID] = struct{}{}
			outcome.accounted = append(outcome.accounted, finding.ID)
		}
		description := "no " + describeExpectation(expectation)
		if len(matches) == 0 {
			pass(description, "no matching finding")
		} else {
			fail(description, fmt.Sprintf("matched %d finding(s), first %s", len(matches), matches[0].Resource))
		}
	}

	for _, expectation := range scenario.Expect.Observations {
		matches := matchObservations(artifact.Report.Observations, expectation)
		description := "observation " + expectation.Kind
		if expectation.Resource != "" {
			description += " " + expectation.Resource
		}
		if expectation.Attr != "" {
			description += " " + expectation.Attr + "=" + expectation.Equals
		}
		detail := fmt.Sprintf("matched %d, expected at least %d", len(matches), expectation.MinCount())
		if len(matches) < expectation.MinCount() {
			fail(description, detail)
		} else {
			pass(description, detail)
		}
	}

	if expectation := scenario.Expect.Coverage; expectation != nil {
		coverage := artifact.Report.Coverage
		if expectation.Status != "" {
			if coverage.Status == expectation.Status {
				pass("coverage status is "+expectation.Status, coverage.Status)
			} else {
				fail("coverage status", "expected "+expectation.Status+", got "+coverage.Status)
			}
		}
		if expectation.Complete != nil {
			if coverage.CoverageComplete == *expectation.Complete {
				pass("coverage_complete matches", fmt.Sprintf("%v", coverage.CoverageComplete))
			} else {
				fail("coverage_complete", fmt.Sprintf("expected %v, got %v", *expectation.Complete, coverage.CoverageComplete))
			}
		}
		if expectation.ExecutionComplete != nil {
			if coverage.ExecutionComplete == *expectation.ExecutionComplete {
				pass("execution_complete matches", fmt.Sprintf("%v", coverage.ExecutionComplete))
			} else {
				fail("execution_complete", fmt.Sprintf("expected %v, got %v", *expectation.ExecutionComplete, coverage.ExecutionComplete))
			}
		}
		if expectation.PermissionDeniedMin != nil {
			minimum := *expectation.PermissionDeniedMin
			if coverage.PermissionDenied >= minimum {
				pass("permission_denied accounted for", fmt.Sprintf("%d", coverage.PermissionDenied))
			} else {
				fail("permission_denied accounted for", fmt.Sprintf("expected at least %d, got %d", minimum, coverage.PermissionDenied))
			}
		}
		for _, root := range expectation.ExcludedRootsInclude {
			if containsString(coverage.ExcludedRoots, root) {
				pass("excluded root reported: "+root, root)
			} else {
				fail("excluded root reported: "+root, strings.Join(coverage.ExcludedRoots, ","))
			}
		}
	}

	if expectation := scenario.Expect.Report; expectation != nil {
		if expectation.Unprivileged != nil {
			if artifact.Report.Scan.Unprivileged == *expectation.Unprivileged {
				pass("scan.unprivileged matches", fmt.Sprintf("%v", artifact.Report.Scan.Unprivileged))
			} else {
				fail("scan.unprivileged", fmt.Sprintf("expected %v, got %v", *expectation.Unprivileged, artifact.Report.Scan.Unprivileged))
			}
		}
		for _, root := range expectation.IncludeRoots {
			if containsString(artifact.Report.Scan.ScanRoots, root) {
				pass("scan root included: "+root, root)
			} else {
				fail("scan root included: "+root, strings.Join(artifact.Report.Scan.ScanRoots, ","))
			}
		}
		for _, root := range expectation.ExcludeRoots {
			if containsString(artifact.Report.Scan.ScanRoots, root) {
				fail("scan root excluded: "+root, strings.Join(artifact.Report.Scan.ScanRoots, ","))
			} else {
				pass("scan root excluded: "+root, root)
			}
		}
	}

	if scenario.Expect.MaxSeverity != "" {
		max, err := models.ParseSeverity(scenario.Expect.MaxSeverity)
		if err != nil {
			fail("max severity is a valid severity", err.Error())
		} else {
			actual := artifact.Report.MaxSeverity()
			if !actual.Valid() || actual.Rank() <= max.Rank() {
				pass("no finding above "+scenario.Expect.MaxSeverity, string(actual))
			} else {
				fail("no finding above "+scenario.Expect.MaxSeverity, string(actual))
			}
		}
	}

	if len(scenario.Scope) > 0 {
		for _, finding := range artifact.Report.Findings {
			if !inScope(finding.Resource, scenario.Scope) {
				continue
			}
			if _, ok := matched[finding.ID]; ok {
				continue
			}
			outcome.unexpected = append(outcome.unexpected, FindingRef{
				Scenario: scenario.ID, RuleID: finding.RuleID,
				Resource: finding.Resource, Severity: string(finding.Severity),
			})
		}
		if len(outcome.unexpected) > 0 {
			fail("no unexpected findings in scope", fmt.Sprintf("%d unexpected", len(outcome.unexpected)))
		}
	}

	outcome.result.Findings = len(artifact.Report.Findings)
	return outcome
}

func describeExpectation(expectation FindingExpectation) string {
	rule := expectation.RuleID
	if rule == "" {
		rule = "any rule"
	}
	resource := expectation.Resource
	if resource == "" {
		resource = "any resource"
	}
	description := "finding " + rule + " on " + resource
	if expectation.Severity != "" {
		description += " severity " + expectation.Severity
	}
	return description
}

func matchFindings(findings []models.Finding, expectation FindingExpectation) []models.Finding {
	matches := []models.Finding{}
	for _, finding := range findings {
		if expectation.RuleID != "" && finding.RuleID != expectation.RuleID {
			continue
		}
		if !resourceMatches(expectation.Resource, expectation.Match, finding.Resource) {
			continue
		}
		matches = append(matches, finding)
	}
	return matches
}

// matchFindingsStrict additionally requires the documented severity and
// confidence, for assertions that a weaker finding does not exist.
func matchFindingsStrict(findings []models.Finding, expectation FindingExpectation) []models.Finding {
	strict := []models.Finding{}
	for _, finding := range matchFindings(findings, expectation) {
		if expectation.Severity != "" && !strings.EqualFold(string(finding.Severity), expectation.Severity) {
			continue
		}
		if expectation.Confidence != "" && !strings.EqualFold(string(finding.Confidence), expectation.Confidence) {
			continue
		}
		strict = append(strict, finding)
	}
	return strict
}

func matchObservations(observations []models.Observation, expectation ObservationExpectation) []models.Observation {
	matches := []models.Observation{}
	for _, observation := range observations {
		if string(observation.Kind) != expectation.Kind {
			continue
		}
		if expectation.Resource != "" && observation.Resource != expectation.Resource {
			continue
		}
		if expectation.Status != "" && string(observation.Status) != expectation.Status {
			continue
		}
		if expectation.Attr != "" {
			value, present := observation.Attr(expectation.Attr)
			if !present {
				continue
			}
			if expectation.Equals != "" && value != expectation.Equals {
				continue
			}
		}
		matches = append(matches, observation)
	}
	return matches
}

func resourceMatches(pattern, mode, value string) bool {
	if pattern == "" {
		return true
	}
	switch mode {
	case "prefix":
		return strings.HasPrefix(value, pattern)
	case "glob":
		matched, err := path.Match(pattern, value)
		return err == nil && matched
	case "any":
		return true
	default: // exact
		return value == pattern
	}
}

func inScope(resource string, scope []string) bool {
	for _, prefix := range scope {
		if strings.HasPrefix(resource, prefix) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func verifyIsolation(isolation Isolation) IsolationReport {
	report := IsolationReport{Probe: isolation, Passed: true}
	report.Checks = []Check{
		{"assessment runs as a non-root user", isolation.NonRoot, fmt.Sprintf("uid=%d", isolation.UID)},
		{"root filesystem is read-only", isolation.ReadOnlyRoot, ""},
		{"effective capabilities are empty", isolation.CapabilitiesDropped, "CapEff=" + isolation.EffectiveCapabilities},
		{"no-new-privileges is set", isolation.NoNewPrivileges, ""},
		{"no routable network access", isolation.NetworkIsolated, "interfaces=" + isolation.NetworkInterfaces + "; " + isolation.NetworkProbe},
		{"Docker socket is absent", !isolation.DockerSocketPresent, ""},
		{"the mounted nulq binary executes", isolation.NulqExecutable, "/opt/nulq/nulq"},
		{"/tmp is writable and size-limited", isolation.TmpWritable, ""},
		{"/tmp refuses execution", isolation.TmpNoExec, ""},
	}
	for _, check := range report.Checks {
		if !check.Passed {
			report.Passed = false
			break
		}
	}
	return report
}

// auditIntegrity checks the invariants that a schema alone cannot express:
// finding identifiers must be unique, each finding must cite evidence, and
// every cited evidence ID must resolve inside the same report. A duplicate is
// either the same ID twice or the same rule, resource and title under two IDs.
func auditIntegrity(report models.Report) ([]FindingRef, int, int) {
	evidenceIDs := make(map[string]struct{}, len(report.Evidence))
	for _, item := range report.Evidence {
		evidenceIDs[item.ID] = struct{}{}
	}
	seenID := map[string]struct{}{}
	seenKey := map[string]struct{}{}
	var duplicates []FindingRef
	dangling := 0
	withoutEvidence := 0
	for _, finding := range report.Findings {
		key := finding.RuleID + "\x00" + finding.Resource + "\x00" + finding.Title
		_, duplicateID := seenID[finding.ID]
		_, duplicateKey := seenKey[key]
		if duplicateID || duplicateKey {
			duplicates = append(duplicates, FindingRef{
				Scenario: "integrity", RuleID: finding.RuleID,
				Resource: finding.Resource, Severity: string(finding.Severity),
			})
		}
		seenID[finding.ID] = struct{}{}
		seenKey[key] = struct{}{}
		if len(finding.Evidence) == 0 {
			withoutEvidence++
		}
		for _, id := range finding.Evidence {
			if _, ok := evidenceIDs[id]; !ok {
				dangling++
			}
		}
	}
	return duplicates, dangling, withoutEvidence
}

func collectionErrors(name string, report models.Report) []string {
	var out []string
	for _, collector := range report.Stats.Collectors {
		if collector.Status != "ok" {
			out = append(out, fmt.Sprintf("%s: collector %s failed: %s", name, collector.Name, collector.Error))
		}
	}
	for _, root := range report.Coverage.Roots {
		if root.TraversalErrors > 0 {
			out = append(out, fmt.Sprintf("%s: %d entries under %s could not be traversed (%d permission denied)",
				name, root.TraversalErrors, root.Root, root.PermissionDenied))
		}
	}
	if len(out) > 40 {
		out = append(out[:40], fmt.Sprintf("%s: %d further collection messages omitted", name, len(out)-40))
	}
	return out
}
