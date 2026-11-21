package cli

import (
	"context"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/dustin04x/nulq/internal/app"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/platform/linux/filesystem"
	"github.com/dustin04x/nulq/internal/rules"
)

func (a *App) runScan(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var roots multiValue
	format := flags.String("format", "terminal", "report format: terminal, json, jsonl or markdown")
	output := flags.String("output", "", "write the report to a file (\"-\" for stdout)")
	modules := flags.String("modules", "", "comma-separated modules to run (default: all)")
	ruleIDs := flags.String("rules", "", "comma-separated rule IDs to run (default: all in the selected modules)")
	concurrency := flags.Int("concurrency", runtime.NumCPU(), "maximum concurrent collectors and rules")
	ruleTimeout := flags.Duration("rule-timeout", 20*time.Second, "per-rule evaluation timeout")
	collectorTimeout := flags.Duration("collector-timeout", 2*time.Minute, "per-collector timeout")
	totalTimeout := flags.Duration("timeout", 5*time.Minute, "overall scan timeout")
	maxFiles := flags.Int("max-files", filesystem.DefaultMaxFiles, "maximum filesystem entries inspected per root")
	includeObservations := flags.Bool("observations", false, "include collected observations in the report")
	failOn := flags.String("fail-on", "", "exit 3 when a finding at or above this severity exists (INFO..CRITICAL)")
	color := flags.String("color", "auto", "colour mode: auto, always or never")
	quiet := flags.Bool("quiet", false, "suppress informational output and findings below MEDIUM")
	verbose := flags.Bool("verbose", false, "emit diagnostic logging to stderr")
	flags.Var(&roots, "root", "restrict filesystem discovery to this root (repeatable)")

	if err := flags.Parse(args); err != nil {
		if stderrors.Is(err, flag.ErrHelp) {
			a.printScanUsage(a.Stdout)
			return ExitOK
		}
		return a.usageError("scan", err)
	}
	if flags.NArg() > 0 {
		return a.usageError("scan", fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	if err := validateFormat(*format); err != nil {
		return a.usageError("scan", err)
	}
	if err := validateColor(*color); err != nil {
		return a.usageError("scan", err)
	}
	switch {
	case *quiet && *verbose:
		return a.usageError("scan", fmt.Errorf("--quiet and --verbose are mutually exclusive"))
	case *concurrency <= 0:
		return a.usageError("scan", fmt.Errorf("--concurrency must be positive"))
	case *maxFiles <= 0:
		return a.usageError("scan", fmt.Errorf("--max-files must be positive"))
	case *ruleTimeout <= 0:
		return a.usageError("scan", fmt.Errorf("--rule-timeout must be positive"))
	case *collectorTimeout <= 0:
		return a.usageError("scan", fmt.Errorf("--collector-timeout must be positive"))
	case *totalTimeout <= 0:
		return a.usageError("scan", fmt.Errorf("--timeout must be positive"))
	}

	// Validate rule selection before scanning so a typo is a usage error
	// rather than a partially executed assessment.
	ruleSet, err := rules.Registry()
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq scan: %v\n", err)
		return ExitError
	}
	if _, err := ruleSet.Select(splitCSV(*modules), splitCSV(*ruleIDs)); err != nil {
		return a.usageError("scan", err)
	}

	var failSeverity models.Severity
	if *failOn != "" {
		parsed, err := models.ParseSeverity(*failOn)
		if err != nil {
			return a.usageError("scan", err)
		}
		failSeverity = parsed
	}

	scanCtx := ctx
	var cancel context.CancelFunc
	if *totalTimeout > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, *totalTimeout)
		defer cancel()
	}

	logger := a.logger(*quiet, *verbose)
	report, scanErr := app.Scan(scanCtx, app.ScanConfig{
		Modules:             splitCSV(*modules),
		RuleIDs:             splitCSV(*ruleIDs),
		Concurrency:         *concurrency,
		RuleTimeout:         *ruleTimeout,
		CollectorTimeout:    *collectorTimeout,
		ScanRoots:           roots,
		MaxFiles:            *maxFiles,
		IncludeObservations: *includeObservations,
		Tool:                a.Version,
	}, logger)

	writer, closeOutput, err := a.openOutput(*output)
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq scan: %v\n", err)
		return ExitError
	}
	renderErr := renderScanReport(writer, report, *format, renderOptions{
		Color: colorEnabled(*color, writer, a.Getenv),
		Quiet: *quiet,
		Width: terminalWidth(a.Getenv),
	})
	closeErr := closeOutput()
	if renderErr != nil {
		fmt.Fprintf(a.Stderr, "nulq scan: writing report: %v\n", renderErr)
		return ExitError
	}
	if closeErr != nil {
		fmt.Fprintf(a.Stderr, "nulq scan: closing output: %v\n", closeErr)
		return ExitError
	}

	if *output != "" && *output != "-" && !*quiet {
		fmt.Fprintf(a.Stderr, "nulq: wrote %s report with %d findings to %s\n", *format, len(report.Findings), *output)
	}
	if scanErr != nil {
		fmt.Fprintf(a.Stderr, "nulq scan: %v\n", scanErr)
		return ExitError
	}
	if failSeverity.Valid() && report.MaxSeverity().AtLeast(failSeverity) {
		return ExitFindings
	}
	return ExitOK
}

func (a *App) printScanUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: nulq scan [flags]

Run a read-only assessment, evaluate detection rules and emit a report.

Flags:
  --format string            terminal, json, jsonl or markdown (default "terminal")
  --output string            write the report to a file ("-" for stdout)
  --modules string           comma-separated modules to run (identity, filesystem, process, system)
  --rules string             comma-separated rule IDs to run
  --root string              restrict filesystem discovery to this root (repeatable)
  --max-files int            maximum entries inspected per filesystem (default 1000000)
  --concurrency int          maximum concurrent collectors and rules
  --rule-timeout duration    per-rule timeout (default 20s)
  --collector-timeout duration  per-collector timeout (default 2m)
  --timeout duration         overall scan timeout (default 5m)
  --observations             include collected observations in the report
  --fail-on string           exit 3 when a finding at or above this severity exists
  --color string             auto, always or never (default "auto")
  --quiet                    suppress informational output and findings below MEDIUM
  --verbose                  emit diagnostic logging to stderr

Examples:
  nulq scan
  nulq scan --format json --output report.json
  nulq scan --modules filesystem,identity --fail-on high
  nulq scan --format markdown --output assessment.md
`)
}
