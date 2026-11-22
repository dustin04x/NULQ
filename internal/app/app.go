// Package app wires collectors, rules and reporting into a scan.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/executor"
	"github.com/dustin04x/nulq/internal/platform/linux/container"
	"github.com/dustin04x/nulq/internal/platform/linux/cron"
	"github.com/dustin04x/nulq/internal/platform/linux/filesystem"
	"github.com/dustin04x/nulq/internal/platform/linux/identity"
	"github.com/dustin04x/nulq/internal/platform/linux/process"
	"github.com/dustin04x/nulq/internal/platform/linux/sudo"
	"github.com/dustin04x/nulq/internal/platform/linux/system"
	"github.com/dustin04x/nulq/internal/platform/linux/systemd"
	"github.com/dustin04x/nulq/internal/rules"
	"github.com/dustin04x/nulq/internal/version"
)

// ScanConfig configures one assessment.
type ScanConfig struct {
	Modules             []string
	RuleIDs             []string
	Concurrency         int
	RuleTimeout         time.Duration
	CollectorTimeout    time.Duration
	ScanRoots           []string
	MaxFiles            int
	PathEnv             string
	IncludeObservations bool
	Deterministic       bool
	Tool                version.Info
	// ProcRoot overrides the proc filesystem root. Normal CLI usage leaves it
	// empty; synthetic integration tests point it at a controlled tree so the
	// real collector and rule pipeline can be exercised without touching host
	// processes.
	ProcRoot string
}

// Limitations are the invariants a NULQ report must repeat so readers do not
// over-read its findings.
var Limitations = []string{
	"Permission checks use ownership and mode bits together with POSIX ACLs when ACL state is observed; security-module policy is not evaluated, and unreadable or malformed ACL state is reported as unknown rather than assumed.",
	"Process observations cover numeric identity, lifecycle and executable-path context only; environments, command lines, memory maps and file descriptors are never read, so process intent and runtime behavior are not assessed.",
	"Discovery runs with the privileges of the invoking user; unreadable paths are reported as unavailable, never bypassed.",
	"Findings describe observed configuration relationships. NULQ does not execute discovered binaries or services and does not attempt exploitation.",
	"The absence of a finding is not evidence that the system is secure.",
}

// Scan runs an assessment and returns the resulting report. A non-nil error
// indicates the scan was interrupted or an invariant failed; the report still
// contains everything that was observed.
func Scan(ctx context.Context, cfg ScanConfig, logger *slog.Logger) (models.Report, error) {
	ruleSet, err := rules.Registry()
	if err != nil {
		return models.Report{}, err
	}
	selected, err := ruleSet.Select(cfg.Modules, cfg.RuleIDs)
	if err != nil {
		return models.Report{}, err
	}

	collectors := []interfaces.Collector{
		system.NewCollector(),
		identity.NewCollector(),
	}
	if needsFilesystem(selected) {
		pathEnv := cfg.PathEnv
		if pathEnv == "" {
			pathEnv = os.Getenv("PATH")
		}
		collectors = append(collectors, filesystem.NewCollector(filesystem.Options{
			Roots:    cfg.ScanRoots,
			PathEnv:  pathEnv,
			MaxFiles: cfg.MaxFiles,
		}, logger))
	}
	if needsProcess(selected) {
		collectors = append(collectors, process.NewCollector(process.Options{ProcRoot: cfg.ProcRoot}, logger))
	}
	if needsSystemd(selected) {
		collectors = append(collectors, systemd.NewCollector(systemd.Options{}, logger))
	}
	if needsSudo(selected) {
		collectors = append(collectors, sudo.NewCollector())
	}
	if needsCron(selected) {
		collectors = append(collectors, cron.NewCollector())
	}
	if needsContainer(selected) {
		collectors = append(collectors, container.NewCollector())
	}

	engine := executor.New(selected, collectors, executor.Options{
		Concurrency:      cfg.Concurrency,
		RuleTimeout:      cfg.RuleTimeout,
		CollectorTimeout: cfg.CollectorTimeout,
	}, logger)

	result, runErr := engine.Run(ctx)
	report := buildReport(cfg, selected, result)
	if !cfg.IncludeObservations {
		report.Observations = nil
	}
	return report, runErr
}

// SystemInfo collects platform facts without evaluating rules.
func SystemInfo(ctx context.Context, tool version.Info, logger *slog.Logger) (models.Report, error) {
	collectors := []interfaces.Collector{
		system.NewCollector(),
		identity.NewCollector(),
		process.NewCollector(process.Options{}, logger),
	}
	engine := executor.New(nil, collectors, executor.Options{
		Concurrency:      len(collectors),
		CollectorTimeout: time.Minute,
	}, logger)

	result, runErr := engine.Run(ctx)
	report := buildReport(ScanConfig{Tool: tool, IncludeObservations: true}, nil, result)
	return report, runErr
}

func buildReport(cfg ScanConfig, selected []interfaces.Rule, result executor.Result) models.Report {
	host := hostInfo(result.Observations)
	startedAt := result.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	// Deterministic mode normalizes all wall-clock timestamps so identical
	// input produces byte-identical JSON. The zero time is used as the
	// reference so output is reproducible across runs.
	if cfg.Deterministic {
		startedAt = time.Time{}
	}

	stats := models.Stats{
		Observations: len(result.Observations),
		Findings:     len(result.Findings),
		Evidence:     len(result.Evidence),
	}
	for _, outcome := range result.Rules {
		stats.Rules.Total++
		switch outcome.Status {
		case executor.StatusOK:
			stats.Rules.Executed++
		case executor.StatusSkipped:
			stats.Rules.Skipped++
		case executor.StatusFailed:
			stats.Rules.Failed++
		}
	}
	for _, obs := range result.Observations {
		if obs.Status != models.StatusComplete {
			stats.UnavailableObservations++
		}
	}
	for _, collector := range result.Collectors {
		stats.Collectors = append(stats.Collectors, models.CollectorStatus{
			Name:         collector.Name,
			Status:       collector.Status,
			Observations: collector.Observations,
			DurationMS:   collector.Duration.Milliseconds(),
			Error:        collector.Error,
		})
	}

	modules := make([]string, 0, len(selected))
	seen := make(map[string]struct{}, len(selected))
	for _, rule := range selected {
		module := rule.Metadata().Module
		if _, ok := seen[module]; ok {
			continue
		}
		seen[module] = struct{}{}
		modules = append(modules, module)
	}
	sort.Strings(modules)

	limitations := append([]string{}, Limitations...)
	if truncatedRoots := truncatedRootList(result.Observations); len(truncatedRoots) > 0 {
		limitations = append(limitations, "Filesystem traversal was truncated by the entry budget for: "+
			strings.Join(truncatedRoots, ", ")+". Findings may be incomplete.")
	}
	if unreadable := scanErrorCount(result.Observations); unreadable > 0 {
		limitations = append(limitations, fmt.Sprintf(
			"%d filesystem entries could not be read (permission denied or I/O error); those subtrees were not assessed.", unreadable))
	}
	if cfg.ScanRoots != nil {
		limitations = append(limitations, "The scan was restricted to caller-supplied roots: "+
			strings.Join(cfg.ScanRoots, ", ")+".")
	}

	report := models.Report{
		SchemaVersion: models.SchemaVersion,
		Tool: models.ToolInfo{
			Name:      "nulq",
			Version:   cfg.Tool.Version,
			Commit:    cfg.Tool.Commit,
			BuildDate: cfg.Tool.BuildDate,
			GoVersion: cfg.Tool.GoVersion,
			Platform:  cfg.Tool.Platform,
		},
		Host: host,
		Scan: models.ScanInfo{
			ReportID:     models.NewReportID(host.Hostname, startedAt),
			StartedAt:    startedAt.UTC(),
			FinishedAt:   result.FinishedAt.UTC(),
			DurationMS:   result.Duration().Milliseconds(),
			Modules:      modules,
			ScanRoots:    scanRoots(cfg, result.Observations),
			Unprivileged: os.Geteuid() != 0,
			Partial:      scanIsPartial(result),
		},
		Findings:     result.Findings,
		Evidence:     result.Evidence,
		Observations: sortedObservations(result.Observations),
		Stats:        stats,
		Coverage:     buildCoverage(result),
		Limitations:  limitations,
	}

	if cfg.Deterministic {
		normalizeDeterministic(&report, startedAt)
	}

	report.Normalize()
	return report
}

// normalizeDeterministic replaces wall-clock timestamps with the deterministic
// reference so two scans of identical input produce byte-identical JSON.
func normalizeDeterministic(report *models.Report, ref time.Time) {
	report.Scan.StartedAt = ref.UTC()
	report.Scan.FinishedAt = ref.UTC()
	report.Scan.DurationMS = 0
	report.Scan.ReportID = models.NewReportID(report.Host.Hostname, ref)

	for i := range report.Findings {
		report.Findings[i].DetectedAt = ref.UTC()
	}
	for i := range report.Observations {
		report.Observations[i].CollectedAt = ref.UTC()
	}
	for i := range report.Evidence {
		report.Evidence[i].CollectedAt = ref.UTC()
	}
}
func hostInfo(observations []models.Observation) models.HostInfo {
	host := models.HostInfo{
		Hostname:     "unknown-host",
		Architecture: "unknown",
	}
	for _, obs := range observations {
		if obs.Kind != models.KindSystemInfo {
			continue
		}
		value := func(key, fallback string) string {
			if observed, ok := obs.Attr(key); ok && observed != "" {
				return observed
			}
			return fallback
		}
		host.Hostname = value(models.AttrHostname, host.Hostname)
		host.OSID = value(models.AttrOSID, "")
		host.OSName = value(models.AttrOSName, "")
		host.OSVersion = value(models.AttrOSVersion, "")
		host.KernelRelease = value(models.AttrKernelRelease, "")
		host.Architecture = value(models.AttrArchitecture, host.Architecture)
		host.Container = obs.Bool(models.AttrContainer)
		host.ContainerRuntime = value(models.AttrContainerRuntime, "")
		if modules, ok := obs.Attr(models.AttrLSMList); ok && modules != "" {
			host.SecurityModules = strings.Split(modules, ",")
		}
		break
	}
	return host
}

func needsFilesystem(selected []interfaces.Rule) bool {
	filesystemKinds := map[models.Kind]struct{}{
		models.KindFile:           {},
		models.KindDirectory:      {},
		models.KindPathEntry:      {},
		models.KindMount:          {},
		models.KindFilesystemScan: {},
	}
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if _, ok := filesystemKinds[kind]; ok {
				return true
			}
		}
	}
	return false
}

func needsProcess(selected []interfaces.Rule) bool {
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if kind == models.KindProcess {
				return true
			}
		}
	}
	return false
}

func needsSystemd(selected []interfaces.Rule) bool {
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if kind == models.KindSystemdUnit {
				return true
			}
		}
	}
	return false
}

func needsSudo(selected []interfaces.Rule) bool {
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if kind == models.KindSudoRule {
				return true
			}
		}
	}
	return false
}

func needsCron(selected []interfaces.Rule) bool {
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if kind == models.KindCronJob {
				return true
			}
		}
	}
	return false
}

func needsContainer(selected []interfaces.Rule) bool {
	for _, rule := range selected {
		for _, kind := range rule.Metadata().Required {
			if kind == models.KindContainerIndicator {
				return true
			}
		}
	}
	return false
}

func scanRoots(cfg ScanConfig, observations []models.Observation) []string {
	if len(cfg.ScanRoots) > 0 {
		return append([]string{}, cfg.ScanRoots...)
	}
	var roots []string
	for _, obs := range observations {
		if obs.Kind != models.KindFilesystemScan || obs.Resource == "mounts" {
			continue
		}
		roots = append(roots, obs.Resource)
	}
	sort.Strings(roots)
	return roots
}

func scanIsPartial(result executor.Result) bool {
	for _, collector := range result.Collectors {
		if collector.Status != executor.StatusOK {
			return true
		}
	}
	for _, rule := range result.Rules {
		if rule.Status == executor.StatusFailed {
			return true
		}
	}
	for _, obs := range result.Observations {
		if obs.Status == models.StatusPartial || obs.Status == models.StatusError {
			return true
		}
	}
	return false
}

func scanErrorCount(observations []models.Observation) int {
	total := 0
	for _, obs := range observations {
		if obs.Kind != models.KindFilesystemScan {
			continue
		}
		if count, ok := obs.Int(models.AttrScanErrors); ok {
			total += int(count)
		}
	}
	return total
}

func truncatedRootList(observations []models.Observation) []string {
	var roots []string
	for _, obs := range observations {
		if obs.Kind == models.KindFilesystemScan && obs.Bool(models.AttrTruncated) {
			roots = append(roots, obs.Resource)
		}
	}
	sort.Strings(roots)
	return roots
}

// buildCoverage classifies the scan's completeness from the artifacts the
// engine already produced. It never infers success: a collector or rule that
// did not finish makes coverage fail, and unreadable or truncated scope makes
// it partial even when every rule executed.
func buildCoverage(result executor.Result) models.Coverage {
	coverage := models.Coverage{
		Status:           models.CoverageComplete,
		TruncatedRoots:   []string{},
		ExcludedRoots:    []string{},
		SkippedRules:     []models.SkippedRule{},
		FailedOperations: []models.OperationFailure{},
		Roots:            []models.RootCoverage{},
	}

	executionComplete := true
	for _, collector := range result.Collectors {
		if collector.Status != executor.StatusOK {
			executionComplete = false
			coverage.FailedOperations = append(coverage.FailedOperations, operationFailure(
				"collector:"+collector.Name, collector.Class, collector.Error))
		}
	}
	for _, rule := range result.Rules {
		switch rule.Status {
		case executor.StatusFailed:
			executionComplete = false
			coverage.FailedOperations = append(coverage.FailedOperations, operationFailure(
				"rule:"+rule.ID, rule.Class, rule.Error))
		case executor.StatusSkipped:
			// A skip caused by cancellation or timeout means the rule never
			// produced a verdict, so execution is incomplete. A skip caused
			// by genuinely missing observations is recorded but does not
			// downgrade coverage by itself.
			if rule.Class == string(nulqerr.ClassCanceled) || rule.Class == string(nulqerr.ClassTimeout) {
				executionComplete = false
				coverage.FailedOperations = append(coverage.FailedOperations, operationFailure(
					"rule:"+rule.ID, rule.Class, rule.Reason))
				continue
			}
			coverage.SkippedRules = append(coverage.SkippedRules, models.SkippedRule{
				RuleID: rule.ID,
				Reason: rule.Reason,
			})
		}
	}

	seenExcluded := map[string]struct{}{}
	for _, obs := range result.Observations {
		if obs.Kind != models.KindMount {
			continue
		}
		if obs.Bool(models.AttrAssessed) {
			continue
		}
		if _, ok := obs.Attr(models.AttrExclusionReason); !ok {
			continue
		}
		if _, seen := seenExcluded[obs.Resource]; seen {
			continue
		}
		seenExcluded[obs.Resource] = struct{}{}
		coverage.ExcludedRoots = append(coverage.ExcludedRoots, obs.Resource)
	}

	for _, obs := range result.Observations {
		if obs.Status != models.StatusComplete {
			coverage.UnavailableObservations++
		}
		if obs.Error != nil && obs.Error.Class == string(nulqerr.ClassUnsupported) {
			coverage.UnsupportedObservations++
		}
		if obs.Kind != models.KindFilesystemScan || obs.Resource == "mounts" {
			continue
		}

		files, _ := obs.Int(models.AttrFilesVisited)
		dirs, _ := obs.Int(models.AttrDirsVisited)
		errorsObserved, _ := obs.Int(models.AttrScanErrors)
		denied, _ := obs.Int(models.AttrScanDenied)
		root := models.RootCoverage{
			Root:                obs.Resource,
			Status:              models.CoverageComplete,
			FilesExamined:       int(files),
			DirectoriesExamined: int(dirs),
			TraversalErrors:     int(errorsObserved),
			PermissionDenied:    int(denied),
			Truncated:           obs.Bool(models.AttrTruncated),
		}
		switch {
		case obs.Status == models.StatusUnavailable:
			root.Status = "unavailable"
		case root.Truncated || root.TraversalErrors > 0:
			root.Status = models.CoveragePartial
		}

		coverage.Roots = append(coverage.Roots, root)
		coverage.FilesExamined += root.FilesExamined
		coverage.DirectoriesExamined += root.DirectoriesExamined
		coverage.TraversalErrors += root.TraversalErrors
		coverage.PermissionDenied += root.PermissionDenied
		if root.Truncated {
			coverage.TruncatedRoots = append(coverage.TruncatedRoots, root.Root)
		}
	}
	sort.SliceStable(coverage.Roots, func(i, j int) bool { return coverage.Roots[i].Root < coverage.Roots[j].Root })
	sort.Strings(coverage.TruncatedRoots)
	sort.Strings(coverage.ExcludedRoots)
	sort.SliceStable(coverage.FailedOperations, func(i, j int) bool {
		if coverage.FailedOperations[i].Operation != coverage.FailedOperations[j].Operation {
			return coverage.FailedOperations[i].Operation < coverage.FailedOperations[j].Operation
		}
		return coverage.FailedOperations[i].Class < coverage.FailedOperations[j].Class
	})

	coverage.ExecutionComplete = executionComplete
	coverage.CoverageComplete = executionComplete && len(coverage.TruncatedRoots) == 0 && coverage.TraversalErrors == 0
	switch {
	case !executionComplete:
		coverage.Status = models.CoverageFailed
	case !coverage.CoverageComplete:
		coverage.Status = models.CoveragePartial
	case coverage.UnsupportedObservations > 0:
		coverage.Status = models.CoverageLimited
	}
	return coverage
}

func operationFailure(operation, class, message string) models.OperationFailure {
	if class == "" {
		class = "unclassified"
	}
	return models.OperationFailure{Operation: operation, Class: class, Message: message}
}

func sortedObservations(observations []models.Observation) []models.Observation {
	out := make([]models.Observation, len(observations))
	copy(out, observations)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].ID < out[j].ID
	})
	return out
}
