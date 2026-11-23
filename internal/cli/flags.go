package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/reporting"
)

// multiValue is a repeatable string flag.
type multiValue []string

func (m *multiValue) String() string { return strings.Join(*m, ",") }

func (m *multiValue) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// splitCSV splits a comma-separated flag value, trimming blanks.
func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func validateFormat(value string) error {
	switch value {
	case "terminal", "json", "jsonl", "markdown", "sarif":
		return nil
	}
	return fmt.Errorf("unknown format %q (expected terminal, json, jsonl, markdown or sarif)", value)
}

func validateColor(value string) error {
	switch value {
	case "auto", "always", "never":
		return nil
	}
	return fmt.Errorf("unknown colour mode %q (expected auto, always or never)", value)
}

// logger writes diagnostics to stderr only. Machine-readable output on stdout
// is never contaminated with log records.
func (a *App) logger(quiet, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	switch {
	case quiet:
		level = slog.LevelError
	case verbose:
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(a.Stderr, &slog.HandlerOptions{Level: level}))
}

// openOutput resolves the output destination. Files are created with 0600
// because reports can contain host configuration details.
func (a *App) openOutput(path string) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return a.Stdout, func() error { return nil }, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}

// colorEnabled resolves colour mode; auto requires a terminal on the
// destination and respects NO_COLOR.
func colorEnabled(mode string, w io.Writer, getenv func(string) string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func terminalWidth(getenv func(string) string) int {
	const fallback = 100
	value := strings.TrimSpace(getenv("COLUMNS"))
	if value == "" {
		return fallback
	}
	width, err := strconv.Atoi(value)
	if err != nil || width < 60 {
		return fallback
	}
	if width > 200 {
		return 200
	}
	return width
}

type renderOptions struct {
	Color bool
	Quiet bool
	Width int
}

func renderScanReport(w io.Writer, report models.Report, format string, opts renderOptions) error {
	switch format {
	case "json":
		return reporting.JSON(w, report)
	case "jsonl":
		return reporting.JSONL(w, report)
	case "markdown":
		return reporting.Markdown(w, report)
	case "sarif":
		return reporting.RenderSARIF(w, report)
	default:
		return reporting.Terminal(w, report, reporting.TerminalOptions{
			Color: opts.Color,
			Width: opts.Width,
			Quiet: opts.Quiet,
		})
	}
}
