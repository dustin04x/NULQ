package cli

import (
	"context"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/dustin04x/nulq/internal/app"
	"github.com/dustin04x/nulq/internal/reporting"
)

func (a *App) runSystem(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printSystemUsage(a.Stderr)
		return ExitUsage
	}
	switch args[0] {
	case "info":
		return a.runSystemInfo(ctx, args[1:])
	case "help", "-h", "--help":
		a.printSystemUsage(a.Stdout)
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "nulq system: unknown subcommand %q\n\n", args[0])
		a.printSystemUsage(a.Stderr)
		return ExitUsage
	}
}

func (a *App) runSystemInfo(ctx context.Context, args []string) int {
	flags := flag.NewFlagSet("system info", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "terminal", "output format: terminal or json")
	output := flags.String("output", "", "write the report to a file (\"-\" for stdout)")
	color := flags.String("color", "auto", "colour mode: auto, always or never")
	verbose := flags.Bool("verbose", false, "emit diagnostic logging to stderr")
	timeout := flags.Duration("timeout", time.Minute, "collection timeout")

	if err := flags.Parse(args); err != nil {
		if stderrors.Is(err, flag.ErrHelp) {
			a.printSystemUsage(a.Stdout)
			return ExitOK
		}
		return a.usageError("system info", err)
	}
	if flags.NArg() > 0 {
		return a.usageError("system info", fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	if *format != "terminal" && *format != "json" {
		return a.usageError("system info", fmt.Errorf("unknown format %q (expected terminal or json)", *format))
	}
	if err := validateColor(*color); err != nil {
		return a.usageError("system info", err)
	}
	if *timeout <= 0 {
		return a.usageError("system info", fmt.Errorf("--timeout must be positive"))
	}

	collectionCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	report, collectErr := app.SystemInfo(collectionCtx, a.Version, a.logger(false, *verbose))

	writer, closeOutput, err := a.openOutput(*output)
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq system info: %v\n", err)
		return ExitError
	}
	var renderErr error
	if *format == "json" {
		renderErr = reporting.JSON(writer, report)
	} else {
		renderErr = reporting.SystemInfo(writer, report, reporting.TerminalOptions{
			Color: colorEnabled(*color, writer, a.Getenv),
			Width: terminalWidth(a.Getenv),
		})
	}
	closeErr := closeOutput()
	if renderErr != nil {
		fmt.Fprintf(a.Stderr, "nulq system info: %v\n", renderErr)
		return ExitError
	}
	if closeErr != nil {
		fmt.Fprintf(a.Stderr, "nulq system info: %v\n", closeErr)
		return ExitError
	}
	if collectErr != nil {
		fmt.Fprintf(a.Stderr, "nulq system info: %v\n", collectErr)
		return ExitError
	}
	return ExitOK
}

func (a *App) printSystemUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: nulq system info [flags]

Show host, kernel, security-control and execution-context facts without
evaluating detection rules.

Flags:
  --format string   terminal or json (default "terminal")
  --output string   write output to a file ("-" for stdout)
  --color string    auto, always or never (default "auto")
  --timeout duration  collection timeout (default 1m)
  --verbose         emit diagnostic logging to stderr
`)
}
