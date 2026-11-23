package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/reporting"
	"github.com/dustin04x/nulq/internal/storage"
)

func (a *App) runReport(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.usageError("report", fmt.Errorf("missing subcommand"))
	}
	switch args[0] {
	case "list":
		return a.reportList(args[1:])
	case "show":
		return a.reportShow(args[1:])
	case "export":
		return a.reportExport(args[1:])
	case "delete":
		return a.reportDelete(args[1:])
	default:
		return a.usageError("report", fmt.Errorf("unknown subcommand %q", args[0]))
	}
}

func storeFromArgs(args []string) (*storage.Store, []string, error) {
	// support --data-dir
	dir := ""
	rest := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--data-dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return storage.New(dir), rest, nil
}

func (a *App) reportList(args []string) int {
	store, rest, _ := storeFromArgs(args)
	if len(rest) > 0 {
		return a.usageError("report list", fmt.Errorf("unexpected args"))
	}
	ids, err := store.ListReports()
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq report list: %v\n", err)
		return ExitError
	}
	if len(ids) == 0 {
		fmt.Fprintln(a.Stdout, "No saved reports.")
		return ExitOK
	}
	for _, id := range ids {
		r, err := store.LoadReport(id)
		if err != nil {
			fmt.Fprintf(a.Stdout, "%s  (unreadable: %v)\n", id, err)
			continue
		}
		fmt.Fprintf(a.Stdout, "%s  %s  findings=%d  coverage=%s  version=%s\n",
			reporting.SanitizeLine(r.Scan.ReportID),
			r.Scan.StartedAt.Format("2006-01-02T15:04:05Z"),
			len(r.Findings),
			reporting.SanitizeLine(r.Coverage.Status),
			reporting.SanitizeLine(r.Tool.Version))
	}
	return ExitOK
}

func (a *App) reportShow(args []string) int {
	store, rest, _ := storeFromArgs(args)
	if len(rest) != 1 {
		return a.usageError("report show", fmt.Errorf("expected report id"))
	}
	r, err := store.LoadReport(rest[0])
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq report show: %v\n", err)
		return ExitError
	}
	if err := reporting.Terminal(a.Stdout, r, reporting.TerminalOptions{}); err != nil {
		fmt.Fprintf(a.Stderr, "nulq report show: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func (a *App) reportExport(args []string) int {
	format := "json"
	store, rest, _ := storeFromArgs(args)
	// parse --format
	filtered := []string{}
	for i := 0; i < len(rest); i++ {
		if rest[i] == "--format" && i+1 < len(rest) {
			format = rest[i+1]
			i++
			continue
		}
		filtered = append(filtered, rest[i])
	}
	if len(filtered) != 1 {
		return a.usageError("report export", fmt.Errorf("expected report id"))
	}
	if err := validateFormat(format); err != nil {
		return a.usageError("report export", err)
	}
	r, err := store.LoadReport(filtered[0])
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
		return ExitError
	}
	var w io.Writer = a.Stdout
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
			return ExitError
		}
	case "jsonl":
		if err := reporting.JSONL(w, r); err != nil {
			fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
			return ExitError
		}
	case "markdown":
		if err := reporting.Markdown(w, r); err != nil {
			fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
			return ExitError
		}
	case "sarif":
		if err := reporting.RenderSARIF(w, r); err != nil {
			fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
			return ExitError
		}
	default:
		if err := reporting.Terminal(w, r, reporting.TerminalOptions{}); err != nil {
			fmt.Fprintf(a.Stderr, "nulq report export: %v\n", err)
			return ExitError
		}
	}
	return ExitOK
}

func (a *App) reportDelete(args []string) int {
	store, rest, _ := storeFromArgs(args)
	if len(rest) != 1 {
		return a.usageError("report delete", fmt.Errorf("expected report id"))
	}
	if err := store.DeleteReport(rest[0]); err != nil {
		fmt.Fprintf(a.Stderr, "nulq report delete: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "deleted %s\n", rest[0])
	return ExitOK
}

var _ = models.Report{}
