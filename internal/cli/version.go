package cli

import (
	"encoding/json"
	stderrors "errors"
	"flag"
	"fmt"
	"io"

	"github.com/dustin04x/nulq/internal/version"
)

func (a *App) runVersion(args []string) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "text", "output format: text or json")

	if err := flags.Parse(args); err != nil {
		if stderrors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.Stdout, "Usage: nulq version [--format text|json]\n")
			return ExitOK
		}
		return a.usageError("version", err)
	}
	if flags.NArg() > 0 {
		return a.usageError("version", fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}

	switch *format {
	case "text":
		fmt.Fprintf(a.Stdout, "nulq %s\n", a.Version.Version)
		fmt.Fprintf(a.Stdout, "  commit:     %s\n", a.Version.Commit)
		fmt.Fprintf(a.Stdout, "  build date: %s\n", a.Version.BuildDate)
		fmt.Fprintf(a.Stdout, "  go:         %s\n", a.Version.GoVersion)
		fmt.Fprintf(a.Stdout, "  platform:   %s\n", a.Version.Platform)
		return ExitOK
	case "json":
		payload := struct {
			Name string       `json:"name"`
			Info version.Info `json:"info"`
		}{Name: "nulq", Info: a.Version}
		encoder := json.NewEncoder(a.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintf(a.Stderr, "nulq version: %v\n", err)
			return ExitError
		}
		return ExitOK
	default:
		return a.usageError("version", fmt.Errorf("unknown format %q (expected text or json)", *format))
	}
}
