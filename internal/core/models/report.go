package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// SchemaVersion is the version of the JSON report contract. It changes only
// with a deliberate, documented schema change; new optional fields do not
// require a version bump, removed or re-typed fields do.
//
// 1.1 added the required `coverage` object, which distinguishes execution
// success from observation completeness. See docs/decisions/0009.
const SchemaVersion = "1.1"

// ToolInfo identifies the producing binary.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// HostInfo summarises the assessed host.
type HostInfo struct {
	Hostname         string   `json:"hostname"`
	OSID             string   `json:"os_id,omitempty"`
	OSName           string   `json:"os_name,omitempty"`
	OSVersion        string   `json:"os_version,omitempty"`
	KernelRelease    string   `json:"kernel_release,omitempty"`
	Architecture     string   `json:"architecture"`
	Container        bool     `json:"container"`
	ContainerRuntime string   `json:"container_runtime,omitempty"`
	SecurityModules  []string `json:"security_modules,omitempty"`
}

// ScanInfo describes how the report was produced.
type ScanInfo struct {
	ReportID     string    `json:"report_id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMS   int64     `json:"duration_ms"`
	Modules      []string  `json:"modules"`
	ScanRoots    []string  `json:"scan_roots,omitempty"`
	Unprivileged bool      `json:"unprivileged"`
	Partial      bool      `json:"partial"`
}

// RuleStats summarises rule execution.
type RuleStats struct {
	Total    int `json:"total"`
	Executed int `json:"executed"`
	Skipped  int `json:"skipped"`
	Failed   int `json:"failed"`
}

// CollectorStatus records the outcome of one collector.
type CollectorStatus struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Observations int    `json:"observations"`
	DurationMS   int64  `json:"duration_ms"`
	Error        string `json:"error,omitempty"`
}

// Stats summarises a scan.
type Stats struct {
	Observations            int               `json:"observations"`
	UnavailableObservations int               `json:"unavailable_observations"`
	Findings                int               `json:"findings"`
	Evidence                int               `json:"evidence"`
	Rules                   RuleStats         `json:"rules"`
	Collectors              []CollectorStatus `json:"collectors"`
}

// Coverage status values. They answer a different question from
// ScanInfo.Partial: "how much of the intended scope was actually observed?"
const (
	// CoverageComplete means every collector and rule ran and no filesystem
	// subtree was truncated or unreadable.
	CoverageComplete = "complete"
	// CoveragePartial means collection ran but some filesystem scope was
	// truncated by a budget or could not be traversed (for example permission
	// denied). Findings may be incomplete.
	CoveragePartial = "partial"
	// CoverageLimited means execution succeeded and scope was fully traversed,
	// yet the environment could not supply some observation (class
	// `unsupported`), so part of the intended assessment is unavailable here.
	CoverageLimited = "limited"
	// CoverageFailed means a collector or rule failed; the assessment is not a
	// faithful representation of the requested checks.
	CoverageFailed = "failed"
)

// RootCoverage records traversal outcomes for one filesystem root.
type RootCoverage struct {
	Root                string `json:"root"`
	Status              string `json:"status"`
	FilesExamined       int    `json:"files_examined"`
	DirectoriesExamined int    `json:"directories_examined"`
	TraversalErrors     int    `json:"traversal_errors"`
	PermissionDenied    int    `json:"permission_denied"`
	Truncated           bool   `json:"truncated"`
}

// SkippedRule records a rule that did not evaluate and why. A skip caused by
// a genuinely empty data category (for example no set-owner-ID files exist) is
// "not applicable", not incomplete coverage, so it does not downgrade
// Coverage.Status on its own.
type SkippedRule struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// OperationFailure records a collector or rule that did not complete, with the
// classified reason. Timeouts and cancellations are distinct classes, not free
// text, so consumers can tell an interrupted scan from an internal fault.
type OperationFailure struct {
	Operation string `json:"operation"`
	Class     string `json:"class"`
	Message   string `json:"message,omitempty"`
}

// Coverage separates "the scan ran" from "the scan saw everything it set out
// to see". Consumers must not treat execution_complete as coverage_complete.
type Coverage struct {
	Status                  string             `json:"status"`
	ExecutionComplete       bool               `json:"execution_complete"`
	CoverageComplete        bool               `json:"coverage_complete"`
	FilesExamined           int                `json:"files_examined"`
	DirectoriesExamined     int                `json:"directories_examined"`
	TraversalErrors         int                `json:"traversal_errors"`
	PermissionDenied        int                `json:"permission_denied"`
	UnavailableObservations int                `json:"unavailable_observations"`
	UnsupportedObservations int                `json:"unsupported_observations"`
	TruncatedRoots          []string           `json:"truncated_roots"`
	ExcludedRoots           []string           `json:"excluded_roots"`
	SkippedRules            []SkippedRule      `json:"skipped_rules"`
	FailedOperations        []OperationFailure `json:"failed_operations"`
	Roots                   []RootCoverage     `json:"roots"`
}

// Report is the top-level document emitted by `nulq scan --format json`.
// Findings and Evidence are always present as arrays, never null, so
// consumers can iterate without nil checks.
type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          ToolInfo      `json:"tool"`
	Host          HostInfo      `json:"host"`
	Scan          ScanInfo      `json:"scan"`
	Findings      []Finding     `json:"findings"`
	Evidence      []Evidence    `json:"evidence"`
	Observations  []Observation `json:"observations,omitempty"`
	Stats         Stats         `json:"stats"`
	Coverage      Coverage      `json:"coverage"`
	Limitations   []string      `json:"limitations"`
}

// NewReportID derives a scan identifier from the host and start time.
func NewReportID(hostname string, startedAt time.Time) string {
	h := sha256.Sum256([]byte(hostname + "\x00" + startedAt.UTC().Format(time.RFC3339Nano)))
	return "rpt-" + hex.EncodeToString(h[:6])
}

// Normalize ensures slices are non-nil and findings are deterministically
// ordered. It must be called before rendering.
func (r *Report) Normalize() {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	if r.Evidence == nil {
		r.Evidence = []Evidence{}
	}
	if r.Stats.Collectors == nil {
		r.Stats.Collectors = []CollectorStatus{}
	}
	if r.Limitations == nil {
		r.Limitations = []string{}
	}
	if r.Scan.Modules == nil {
		r.Scan.Modules = []string{}
	}
	if r.Coverage.TruncatedRoots == nil {
		r.Coverage.TruncatedRoots = []string{}
	}
	if r.Coverage.ExcludedRoots == nil {
		r.Coverage.ExcludedRoots = []string{}
	}
	if r.Coverage.FailedOperations == nil {
		r.Coverage.FailedOperations = []OperationFailure{}
	}
	if r.Coverage.SkippedRules == nil {
		r.Coverage.SkippedRules = []SkippedRule{}
	}
	if r.Coverage.Roots == nil {
		r.Coverage.Roots = []RootCoverage{}
	}
	SortFindings(r.Findings)
}

// FindingCountBySeverity counts findings per severity.
func (r Report) FindingCountBySeverity() map[Severity]int {
	counts := make(map[Severity]int, len(AllSeverities()))
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// MaxSeverity returns the highest severity present, or empty when no findings
// were produced.
func (r Report) MaxSeverity() Severity {
	best := Severity("")
	for _, f := range r.Findings {
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}

// String renders a one-line summary.
func (r Report) String() string {
	return fmt.Sprintf("report %s: %d findings, %d observations", r.Scan.ReportID, len(r.Findings), len(r.Observations))
}
