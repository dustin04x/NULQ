// Package scenarios defines the correlation scenarios (COR-001 through COR-005)
// that the M3 correlation engine evaluates. Each scenario has a stable ID, name,
// description, required observation kinds, expected outcomes, confidence rationale,
// and limitations.
//
// These scenarios are designed to be high-quality and meaningful rather than
// dozens of shallow rules. They adapt to the actual data model and operate on
// collected observations and explicitly supplied context.
//
// Critical principle: correlation must never turn missing, partial, stale, or
// unknown evidence into confirmed exposure. Unknown must remain unknown.

package scenarios

import (
	"github.com/dustin04x/nulq/internal/core/models"
)

// CorrelationScenario defines a correlation scenario with its metadata.
// This mirrors the internal.CorrelationScenario but is defined at the package level
// for use by the engine and tests.
type CorrelationScenario struct {
	ID          string
	Name        string
	Description string
	// RequiredObservationKinds are the observation kinds required for this scenario.
	// If any required kind is missing, the scenario cannot be evaluated and produces
	// an "insufficient evidence" result rather than a negative result.
	RequiredObservationKinds []models.Kind
	// ExpectedOutcome is the expected outcome when the scenario is fully supported.
	ExpectedOutcome models.EvaluationOutcome
	// ConfidenceRationale is the expected confidence rationale.
	ConfidenceRationale string
	// Limitations lists known limitations of the scenario.
	Limitations []string
}

// COR001Scenario is the executable replacement exposure scenario.
//
// COR-001: Does a process execute a binary whose location is writable by another identity?
// Is that binary located on a mount with security-relevant flags?
// Does the executable's ownership or mode create a privilege boundary?
// Does an ACL alter the effective permissions that a traditional mode-bit inspection would suggest?
// Does an observed identity have a meaningful relationship to a sensitive executable or directory?
// Are multiple individually weak observations describing one stronger exposure?
// Are multiple findings actually manifestations of the same underlying security condition?
var COR001Scenario = CorrelationScenario{
	ID:          "COR-001",
	Name:        "Executable replacement exposure",
	Description: "Correlate process execution context, executable path and object identity, parent-directory ownership and effective permissions, ACL information, relevant mount flags, and privilege metadata to assess whether a writable executable creates a privilege boundary weakness.",
	RequiredObservationKinds: []models.Kind{
		models.KindProcess,
		models.KindFile,
		models.KindDirectory,
		models.KindMount,
		models.KindExecutionContext,
	},
	ExpectedOutcome:     models.EvaluationPotential,
	ConfidenceRationale: "relationship assessed through mode bits, ownership, mount flags, and ACL state; confidence varies with completeness of each data source",
	Limitations:         []string{"ACL state may be unavailable or malformed; mount metadata may be absent; process identity may be stale or approximated; execution behavior not observed"},
}

// COR002Scenario is the effective permission disagreement scenario.
//
// COR-002: Identify cases where mode bits and ACL evaluation produce materially different effective access conclusions.
//
// Requirements:
// - Apply POSIX ACL precedence and mask semantics.
// - Account for relevant identity and supplementary-group information when available.
// - Preserve UNKNOWN when necessary information is missing.
// - Explain why the final permission conclusion differs from the mode-bit-only interpretation.
var COR002Scenario = CorrelationScenario{
	ID:          "COR-002",
	Name:        "Effective permission disagreement",
	Description: "Identify cases where POSIX mode bits and ACL evaluation produce materially different effective access conclusions, and explain the discrepancy.",
	RequiredObservationKinds: []models.Kind{
		models.KindDirectory,
		models.KindFile,
		models.KindExecutionContext,
	},
	ExpectedOutcome:     models.EvaluationConfirmed,
	ConfidenceRationale: "when both mode bits and ACL state are observed, the ACL evaluation per POSIX precedence supersedes mode-bit-only interpretation; when ACL is unknown, mode bits stand with explicit UNKNOWN limitation",
	Limitations:         []string{"ACL state may be malformed, unreadable, or unsupported; legacy writable-by-current-user attribute may be absent; mask semantics not fully modelled; supplementary group resolution not modelled"},
}

// COR003Scenario is the mount security context scenario.
//
// COR-003: Correlate filesystem observations with mount properties.
//
// Evaluate: nosuid, noexec, nodev, ro, rw
//
// Do not treat mount flags as universal protection. Their impact depends on the object
// and the specific exposure being evaluated.
var COR003Scenario = CorrelationScenario{
	ID:          "COR-003",
	Name:        "Mount security context",
	Description: "Correlate filesystem observations with mount properties (nosuid, noexec, nodev, ro, rw) and evaluate their impact on privilege boundaries and execution constraints.",
	RequiredObservationKinds: []models.Kind{
		models.KindFile,
		models.KindDirectory,
		models.KindMount,
		models.KindExecutionContext,
	},
	ExpectedOutcome:     models.EvaluationPotential,
	ConfidenceRationale: "mount flag impact is object-dependent; nosuid affects SUID/SGID semantics, noexec affects direct execution, ro affects write capability; confidence varies with presence of mount and executable metadata",
	Limitations:         []string{"Mount metadata may be absent for some paths; a mount flag's impact is not universal; ro/noblock interactions with interpreters not evaluated; nodev does not prevent read access"},
}

// COR004Scenario is the shared exposure correlation scenario.
//
// COR-004: Identify multiple findings that refer to the same underlying object, identity, executable, or permission boundary.
//
// Avoid duplicate findings that describe the same condition.
// Preserve distinct security consequences when they genuinely differ.
var COR004Scenario = CorrelationScenario{
	ID:          "COR-004",
	Name:        "Shared exposure correlation",
	Description: "Identify multiple observations or findings that refer to the same underlying object, identity, executable, or permission boundary, and determine whether they describe the same condition or distinct security consequences.",
	RequiredObservationKinds: []models.Kind{
		models.KindFile,
		models.KindDirectory,
		models.KindProcess,
		models.KindMount,
	},
	ExpectedOutcome:     models.EvaluationPotential,
	ConfidenceRationale: "when multiple observation kinds converge on the same resource, the relationship is potentially significant; when they describe different aspects (e.g., mode vs ACL), both are preserved with explicit distinctions",
	Limitations:         []string{"Observation ID stability depends on deterministic ID generation; iteration order must not affect results; repeated scans of equivalent fixtures must produce equivalent results"},
}

// COR005Scenario is the evidence-backed privilege-boundary assessment scenario.
//
// COR-005: Combine relevant observations into a coherent assessment.
//
// The engine must distinguish: Confirmed facts, Potential exposure, Suspicious configuration,
// Insufficient evidence, Contradictory observations. Do not assign HIGH or CRITICAL solely
// because multiple low-confidence observations were combined.
var COR005Scenario = CorrelationScenario{
	ID:          "COR-005",
	Name:        "Evidence-backed privilege-boundary assessment",
	Description: "Combine relevant observations into a coherent privilege-boundary assessment, distinguishing confirmed facts, potential exposure, suspicious configuration, insufficient evidence, and contradictory observations. Do not assign HIGH or CRITICAL solely because multiple low-confidence observations were combined.",
	RequiredObservationKinds: []models.Kind{
		models.KindProcess,
		models.KindFile,
		models.KindDirectory,
		models.KindMount,
		models.KindExecutionContext,
	},
	ExpectedOutcome:     models.EvaluationPotential,
	ConfidenceRationale: "assessment combines confirmed facts (SUID executables observed, ownership/mode metadata), potential exposures (writable by assessed user), and explicit limitations (ACL unknown, mount state unknown); HIGH/CRITICAL never promoted solely by low-confidence accumulation",
	Limitations:         []string{"Confidence never promoted by accumulating low-confidence observations; contradictory observations result in EvaluationContradicted; insufficient evidence results in EvaluationInsufficient; actual exploitability never claimed"},
}

// ScenarioList returns all correlation scenarios in deterministic order.
func ScenarioList() []CorrelationScenario {
	return []CorrelationScenario{
		COR001Scenario,
		COR002Scenario,
		COR003Scenario,
		COR004Scenario,
		COR005Scenario,
	}
}

// ScenarioByID returns the scenario with the given ID, or nil if not found.
func ScenarioByID(id string) *CorrelationScenario {
	for _, s := range ScenarioList() {
		if s.ID == id {
			return &s
		}
	}
	return nil
}
