package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dustin04x/nulq/internal/reporting"
	"github.com/dustin04x/nulq/internal/storage"
)

func (a *App) runBaseline(args []string) int {
	if len(args) == 0 {
		return a.usageError("baseline", fmt.Errorf("missing subcommand"))
	}
	switch args[0] {
	case "create":
		return a.baselineCreate(args[1:])
	case "list":
		return a.baselineList(args[1:])
	case "show":
		return a.baselineShow(args[1:])
	case "delete":
		return a.baselineDelete(args[1:])
	case "compare":
		return a.baselineCompare(args[1:])
	default:
		return a.usageError("baseline", fmt.Errorf("unknown subcommand %q", args[0]))
	}
}

func (a *App) baselineCreate(args []string) int {
	store, rest, _ := storeFromArgs(args)
	name := ""
	reportID := ""
	desc := ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--report":
			if i+1 < len(rest) {
				reportID = rest[i+1]
				i++
			}
		case "--description":
			if i+1 < len(rest) {
				desc = rest[i+1]
				i++
			}
		default:
			if name == "" {
				name = rest[i]
			}
		}
	}
	if name == "" || reportID == "" {
		return a.usageError("baseline create", fmt.Errorf("usage: baseline create <name> --report <report-id>"))
	}
	if err := store.CreateBaseline(name, reportID, desc); err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline create: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "created baseline %s -> %s\n", name, reportID)
	return ExitOK
}

func (a *App) baselineList(args []string) int {
	store, _, _ := storeFromArgs(args)
	names, err := store.ListBaselines()
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline list: %v\n", err)
		return ExitError
	}
	if len(names) == 0 {
		fmt.Fprintln(a.Stdout, "No baselines.")
		return ExitOK
	}
	for _, n := range names {
		b, err := store.LoadBaseline(n)
		if err != nil {
			fmt.Fprintf(a.Stdout, "%s  (unreadable: %v)\n", n, err)
			continue
		}
		fmt.Fprintf(a.Stdout, "%s  report=%s  created=%s\n", reporting.SanitizeLine(b.Name), reporting.SanitizeLine(b.ReportID), b.CreatedAt.Format(time.RFC3339))
	}
	return ExitOK
}

func (a *App) baselineShow(args []string) int {
	store, rest, _ := storeFromArgs(args)
	if len(rest) != 1 {
		return a.usageError("baseline show", fmt.Errorf("expected baseline name"))
	}
	b, err := store.LoadBaseline(rest[0])
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline show: %v\n", err)
		return ExitError
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	fmt.Fprintln(a.Stdout, string(data))
	return ExitOK
}

func (a *App) baselineDelete(args []string) int {
	store, rest, _ := storeFromArgs(args)
	if len(rest) != 1 {
		return a.usageError("baseline delete", fmt.Errorf("expected baseline name"))
	}
	if err := store.DeleteBaseline(rest[0]); err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline delete: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(a.Stdout, "deleted %s\n", rest[0])
	return ExitOK
}

func (a *App) baselineCompare(args []string) int {
	store, rest, _ := storeFromArgs(args)
	name := ""
	reportID := ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--report":
			if i+1 < len(rest) {
				reportID = rest[i+1]
				i++
			}
		default:
			if name == "" {
				name = rest[i]
			}
		}
	}
	if name == "" || reportID == "" {
		return a.usageError("baseline compare", fmt.Errorf("usage: baseline compare <name> --report <report-id>"))
	}
	b, err := store.LoadBaseline(name)
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline compare: %v\n", err)
		return ExitError
	}
	base, err := store.LoadReport(b.ReportID)
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline compare: %v\n", err)
		return ExitError
	}
	cur, err := store.LoadReport(reportID)
	if err != nil {
		fmt.Fprintf(a.Stderr, "nulq baseline compare: %v\n", err)
		return ExitError
	}
	d := storage.CompareReports(base, cur)
	data, _ := json.MarshalIndent(d, "", "  ")
	fmt.Fprintln(a.Stdout, string(data))
	return ExitOK
}

var _ = time.Now
