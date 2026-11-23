// Package cli implements the NULQ command-line interface.
//
// The CLI owns argument parsing, output destinations and exit codes. It does
// no detection work and never prints findings outside the reporting package.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/dustin04x/nulq/internal/version"
)

// Exit codes are part of NULQ's integration contract.
const (
	// ExitOK means the command completed and no failure threshold was met.
	ExitOK = 0
	// ExitError means the command failed at runtime.
	ExitError = 1
	// ExitUsage means the invocation was invalid.
	ExitUsage = 2
	// ExitFindings means --fail-on was set and a finding met the threshold.
	ExitFindings = 3
)

// App is the process surface. Tests drive it directly instead of exec'ing a
// binary.
type App struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Version version.Info
}

// New returns an App bound to the real process environment.
func New() *App {
	return &App{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Getenv:  os.Getenv,
		Version: version.Current(),
	}
}

// Run executes one CLI invocation and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printUsage(a.Stderr)
		return ExitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		a.printUsage(a.Stdout)
		return ExitOK
	case "version", "--version", "-v":
		return a.runVersion(args[1:])
	case "scan":
		return a.runScan(ctx, args[1:])
	case "system":
		return a.runSystem(ctx, args[1:])
	case "rules":
		return a.runRules(args[1:])
	case "report":
		return a.runReport(ctx, args[1:])
	case "baseline":
		return a.runBaseline(args[1:])
	default:
		fmt.Fprintf(a.Stderr, "nulq: unknown command %q\n\n", args[0])
		a.printUsage(a.Stderr)
		return ExitUsage
	}
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprint(w, `NULQ — Linux privilege-boundary discovery and security assessment

Usage:
  nulq <command> [flags]

Commands:
  scan          Run an assessment and emit a report
  system info   Show collected system facts
  rules list    List registered detection rules
  version       Print build metadata
  help          Show this message

Run "nulq <command> -h" for command-specific flags.

Exit codes:
  0  success
  1  runtime failure
  2  usage error
  3  findings at or above the --fail-on threshold

NULQ is read-only: it modifies no system state and executes no discovered
binaries or services.
`)
}

// usageError reports an invalid invocation.
func (a *App) usageError(command string, err error) int {
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq %s: %v\n", command, err)
	}
	fmt.Fprintf(a.Stderr, "Run \"nulq %s -h\" for usage.\n", command)
	return ExitUsage
}
