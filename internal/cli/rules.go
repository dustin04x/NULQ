package cli

import (
	"encoding/json"
	stderrors "errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/rules"
)

func (a *App) runRules(args []string) int {
	if len(args) == 0 {
		a.printRulesUsage(a.Stderr)
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return a.runRulesList(args[1:])
	case "help", "-h", "--help":
		a.printRulesUsage(a.Stdout)
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "nulq rules: unknown subcommand %q\n\n", args[0])
		a.printRulesUsage(a.Stderr)
		return ExitUsage
	}
}

func (a *App) runRulesList(args []string) int {
	flags := flag.NewFlagSet("rules list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "terminal", "output format: terminal or json")
	module := flags.String("module", "", "filter by module")

	if err := flags.Parse(args); err != nil {
		if stderrors.Is(err, flag.ErrHelp) {
			a.printRulesUsage(a.Stdout)
			return ExitOK
		}
		return a.usageError("rules list", err)
	}
	if flags.NArg() > 0 {
		return a.usageError("rules list", fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}
	if *format != "terminal" && *format != "json" {
		return a.usageError("rules list", fmt.Errorf("unknown format %q (expected terminal or json)", *format))
	}

	registry, err := rules.Registry()
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq rules: %v\n", err)
		return ExitError
	}

	metadata := registry.Metadata()
	if *module != "" {
		filtered := metadata[:0]
		found := false
		for _, meta := range metadata {
			if meta.Module == *module {
				filtered = append(filtered, meta)
				found = true
			}
		}
		if !found {
			return a.usageError("rules list", fmt.Errorf("unknown module %q (available: %s)",
				*module, strings.Join(registry.Modules(), ", ")))
		}
		metadata = filtered
	}

	if *format == "json" {
		encoder := json.NewEncoder(a.Stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(metadata); err != nil {
			fmt.Fprintf(a.Stderr, "nulq rules: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	printRuleTable(a.Stdout, metadata)
	return ExitOK
}

func printRuleTable(w io.Writer, metadata []models.RuleMetadata) {
	idWidth, moduleWidth, severityWidth := len("ID"), len("MODULE"), len("SEVERITY")
	for _, meta := range metadata {
		idWidth = max(idWidth, len(meta.ID))
		moduleWidth = max(moduleWidth, len(meta.Module))
		severityWidth = max(severityWidth, len(meta.Severity))
	}
	fmt.Fprintf(w, "%-*s  %-*s  %-*s  %s\n", idWidth, "ID", moduleWidth, "MODULE", severityWidth, "SEVERITY", "NAME")
	for _, meta := range metadata {
		fmt.Fprintf(w, "%-*s  %-*s  %-*s  %s\n", idWidth, meta.ID, moduleWidth, meta.Module, severityWidth, meta.Severity, meta.Name)
	}
	fmt.Fprintf(w, "\n%d rules. Use `nulq rules list --format json` for full metadata.\n", len(metadata))
}

func (a *App) printRulesUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: nulq rules list [flags]

List registered detection rules.

Flags:
  --format string   terminal or json (default "terminal")
  --module string   filter by module (identity, filesystem, system)
`)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
