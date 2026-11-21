// Package executor runs collectors and rules under bounded concurrency.
//
// The engine is the only component allowed to orchestrate a scan. It owns
// cancellation, timeouts, panic isolation and per-rule error isolation, and
// it never lets one failing component abort the whole assessment.
package executor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/aggregation"
	"github.com/dustin04x/nulq/internal/engine/correlation"
	"github.com/dustin04x/nulq/internal/engine/store"
)

// Status values for collector and rule outcomes.
const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
)

// Options configures execution.
type Options struct {
	// Concurrency bounds simultaneous collector and rule evaluations.
	Concurrency int
	// CollectorTimeout bounds one collector. Zero disables the limit.
	CollectorTimeout time.Duration
	// RuleTimeout bounds one rule evaluation. Zero disables the limit.
	RuleTimeout time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// CollectorOutcome records what happened to one collector. Class is the
// classified error category (timeout, canceled, permission_denied, …) so
// coverage can distinguish an interrupted operation from an internal fault.
type CollectorOutcome struct {
	Name         string
	Status       string
	Class        string
	Observations int
	Duration     time.Duration
	Error        string
}

// RuleOutcome records what happened to one rule, with the same classified
// error semantics as CollectorOutcome.
type RuleOutcome struct {
	ID       string
	Status   string
	Class    string
	Reason   string
	Findings int
	Duration time.Duration
	Error    string
}

// Result is the complete output of an engine run.
type Result struct {
	StartedAt    time.Time
	FinishedAt   time.Time
	Observations []models.Observation
	Findings     []models.Finding
	Evidence     []models.Evidence
	Collectors   []CollectorOutcome
	Rules        []RuleOutcome
	Correlation  *correlation.CorrelationResult
}

// Duration returns the wall-clock time of the scan.
func (r Result) Duration() time.Duration {
	return r.FinishedAt.Sub(r.StartedAt)
}

// Engine executes collectors followed by rules.
type Engine struct {
	rules      []interfaces.Rule
	collectors []interfaces.Collector
	opts       Options
	log        *slog.Logger
}

// New builds an engine. Nil loggers are replaced with a discard logger so
// library users are not forced to configure logging.
func New(rules []interfaces.Rule, collectors []interfaces.Collector, opts Options, logger *slog.Logger) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Engine{rules: rules, collectors: collectors, opts: opts, log: logger}
}

// Run performs the assessment. It returns a partial Result alongside an error
// when the scan was canceled or an invariant failed, so callers can report
// what was actually observed.
func (e *Engine) Run(ctx context.Context) (Result, error) {
	result := Result{StartedAt: e.opts.Now()}

	start := time.Now()
	observations, collectorOutcomes := e.collect(ctx)
	result.Collectors = collectorOutcomes
	result.Observations = observations
	e.log.Debug("collection finished", "observations", len(observations), "duration", time.Since(start))

	if err := ctx.Err(); err != nil {
		result.FinishedAt = e.opts.Now()
		return result, nulqerr.Classify("scan", "collectors", err)
	}

	obsStore := store.New(observations)
	result.Observations = obsStore.All()

	findings, evidence, ruleOutcomes := e.evaluate(ctx, obsStore)
	result.Rules = ruleOutcomes

	mergedFindings, mergedEvidence, err := aggregation.Merge(findings, evidence)
	result.FinishedAt = e.opts.Now()
	if err != nil {
		return result, nulqerr.New(nulqerr.ClassInternal, "scan", "aggregation", err)
	}
	result.Findings = mergedFindings
	result.Evidence = mergedEvidence

	// Run correlation engine on the observations and merged results.
	var corrEngine = correlation.NewEngine(obsStore)
	result.Correlation = corrEngine.Run()
	return result, nil
}

func (e *Engine) collect(ctx context.Context) ([]models.Observation, []CollectorOutcome) {
	outcomes := make([]CollectorOutcome, len(e.collectors))
	results := make([][]models.Observation, len(e.collectors))

	sem := make(chan struct{}, e.opts.Concurrency)
	var wg sync.WaitGroup
	for i, collector := range e.collectors {
		wg.Add(1)
		go func(i int, collector interfaces.Collector) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				outcomes[i] = CollectorOutcome{
					Name: collector.Name(), Status: StatusFailed,
					Class: string(nulqerr.ClassCanceled), Error: "scan canceled",
				}
				return
			}

			started := time.Now()
			runCtx := ctx
			var cancel context.CancelFunc
			if e.opts.CollectorTimeout > 0 {
				runCtx, cancel = context.WithTimeout(ctx, e.opts.CollectorTimeout)
			}
			observations, err := collectSafely(runCtx, collector)
			if cancel != nil {
				cancel()
			}

			outcome := CollectorOutcome{
				Name:         collector.Name(),
				Status:       StatusOK,
				Observations: len(observations),
				Duration:     time.Since(started),
			}
			if err != nil {
				outcome.Status = StatusFailed
				outcome.Class = string(nulqerr.ClassOf(err))
				outcome.Error = err.Error()
				e.log.Warn("collector failed", "collector", collector.Name(), "error", err)
			} else {
				e.log.Debug("collector finished", "collector", collector.Name(), "observations", len(observations))
			}
			outcomes[i] = outcome
			results[i] = observations
		}(i, collector)
	}
	wg.Wait()

	total := 0
	for _, obs := range results {
		total += len(obs)
	}
	all := make([]models.Observation, 0, total)
	for _, obs := range results {
		all = append(all, obs...)
	}
	return all, outcomes
}

func collectSafely(ctx context.Context, collector interfaces.Collector) (observations []models.Observation, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = nulqerr.New(nulqerr.ClassInternal, "collect", collector.Name(),
				fmt.Errorf("collector panic: %v", recovered))
			observations = nil
		}
	}()
	return collector.Collect(ctx)
}

type ruleRun struct {
	findings []models.Finding
	evidence []models.Evidence
	outcome  RuleOutcome
}

func (e *Engine) evaluate(ctx context.Context, obsStore *store.Memory) ([]models.Finding, []models.Evidence, []RuleOutcome) {
	runs := make([]ruleRun, len(e.rules))
	sem := make(chan struct{}, e.opts.Concurrency)
	var wg sync.WaitGroup

	for i, rule := range e.rules {
		wg.Add(1)
		go func(i int, rule interfaces.Rule) {
			defer wg.Done()
			runs[i] = e.evaluateRule(ctx, sem, rule, obsStore)
		}(i, rule)
	}
	wg.Wait()

	var findings []models.Finding
	var evidence []models.Evidence
	outcomes := make([]RuleOutcome, 0, len(runs))
	for _, run := range runs {
		findings = append(findings, run.findings...)
		evidence = append(evidence, run.evidence...)
		outcomes = append(outcomes, run.outcome)
	}
	return findings, evidence, outcomes
}

func (e *Engine) evaluateRule(ctx context.Context, sem chan struct{}, rule interfaces.Rule, obsStore *store.Memory) ruleRun {
	meta := rule.Metadata()
	run := ruleRun{outcome: RuleOutcome{ID: meta.ID}}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		run.outcome.Status = StatusSkipped
		run.outcome.Class = string(nulqerr.ClassCanceled)
		run.outcome.Reason = "scan canceled"
		return run
	}

	started := time.Now()
	defer func() { run.outcome.Duration = time.Since(started) }()

	if err := ctx.Err(); err != nil {
		run.outcome.Status = StatusSkipped
		run.outcome.Class = string(nulqerr.ClassCanceled)
		run.outcome.Reason = "scan canceled"
		return run
	}

	if missing := missingKinds(obsStore, meta.Required); len(missing) > 0 {
		run.outcome.Status = StatusSkipped
		run.outcome.Reason = "missing observations: " + strings.Join(missing, ", ")
		e.log.Debug("rule skipped", "rule", meta.ID, "reason", run.outcome.Reason)
		return run
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if e.opts.RuleTimeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, e.opts.RuleTimeout)
		defer cancel()
	}

	result, err := evaluateSafely(runCtx, rule, obsStore)
	if err == nil && runCtx.Err() != nil {
		// A rule that ignores cancellation must not be reported as healthy.
		err = nulqerr.Classify("rule", meta.ID, runCtx.Err())
	}
	if err != nil {
		run.outcome.Status = StatusFailed
		run.outcome.Class = string(nulqerr.ClassOf(err))
		run.outcome.Error = err.Error()
		e.log.Warn("rule failed", "rule", meta.ID, "error", err)
		return run
	}
	if err := validateRuleOutput(meta, result.Findings, result.Evidence); err != nil {
		run.outcome.Status = StatusFailed
		run.outcome.Error = "invalid rule output: " + err.Error()
		e.log.Warn("rule produced invalid output", "rule", meta.ID, "error", err)
		return run
	}

	run.findings = result.Findings
	run.evidence = result.Evidence
	run.outcome.Status = StatusOK
	run.outcome.Findings = len(result.Findings)
	e.log.Debug("rule finished", "rule", meta.ID, "findings", len(result.Findings))
	return run
}

func evaluateSafely(ctx context.Context, rule interfaces.Rule, obs interfaces.ObservationSet) (result models.RuleResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = nulqerr.New(nulqerr.ClassInternal, "rule", rule.Metadata().ID,
				fmt.Errorf("rule panic: %v", recovered))
			result = models.RuleResult{}
		}
	}()
	return rule.Evaluate(ctx, obs)
}

func missingKinds(obsStore *store.Memory, required []models.Kind) []string {
	var missing []string
	for _, kind := range required {
		if !obsStore.Has(kind) {
			missing = append(missing, string(kind))
		}
	}
	return missing
}

func validateRuleOutput(meta models.RuleMetadata, findings []models.Finding, evidence []models.Evidence) error {
	evidenceIDs := make(map[string]struct{}, len(evidence))
	for _, item := range evidence {
		evidenceIDs[item.ID] = struct{}{}
	}
	for _, finding := range findings {
		if finding.RuleID != meta.ID {
			return fmt.Errorf("rule %s produced finding %s attributed to rule %s", meta.ID, finding.ID, finding.RuleID)
		}
		if err := finding.Validate(); err != nil {
			return err
		}
		for _, id := range finding.Evidence {
			if _, ok := evidenceIDs[id]; !ok {
				return fmt.Errorf("rule %s finding %s cites evidence %s that the rule did not return", meta.ID, finding.ID, id)
			}
		}
	}
	return nil
}
