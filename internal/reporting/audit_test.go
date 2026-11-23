package reporting

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

// hostileReport builds a report whose identifier and free-text fields contain
// terminal escape sequences, C1 control bytes and a backtick. These values
// never originate from a live scan of a well-behaved system; they model a
// report that was tampered with on disk or produced by a hostile host, which
// the renderers must neutralise before the bytes reach a terminal.
func hostileReport() models.Report {
	rep := sampleReport()
	const (
		esc  = "\x1b[2J\x1b[31m" // clear screen + red
		c1   = "\u009b31m"       // 8-bit CSI
		bell = "\x07"
	)
	rep.Tool.Version = "test" + esc + "v1"
	rep.Scan.ReportID = "rpt-" + esc + "evil"
	rep.Coverage.Status = "partial" + bell
	f := &rep.Findings[0]
	f.RuleID = "NULQ-T-001" + esc
	f.RuleVersion = "1.0.0" + c1
	f.Confidence = models.ConfidenceHigh
	f.Title = "Title" + bell
	f.Resource = "/tmp/evil" + esc + "name"
	for i := range rep.Evidence {
		rep.Evidence[i].ID = "ev-" + esc + "1"
		rep.Evidence[i].Resource = "/tmp/evil" + esc
		rep.Evidence[i].ObservedValue = "0777" + c1
	}
	rep.Limitations = []string{"limit" + esc}
	return rep
}

func assertNoEscape(t *testing.T, label, output string) {
	t.Helper()
	if strings.ContainsRune(output, '\x1b') {
		t.Fatalf("%s: output contains ESC (0x1b)\n%q", label, output)
	}
	if strings.Contains(output, "\u009b") {
		t.Fatalf("%s: output contains C1 CSI (U+009B)\n%q", label, output)
	}
	if strings.ContainsRune(output, '\x07') {
		t.Fatalf("%s: output contains BEL (0x07)\n%q", label, output)
	}
}

// TestSanitizeLineStripsControlBytes pins the exported helper used by the CLI
// to neutralise untrusted persisted fields before printing them.
func TestSanitizeLineStripsControlBytes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"a\x1b[31mb", "a[31mb"},
		{"a\nb", "a b"},
		{"a\tb", "a b"},
		{"a\u009bb", "ab"},
		{"a\x07b", "ab"},
		{"nul\x00byte", "nulbyte"},
	}
	for _, tc := range cases {
		if got := SanitizeLine(tc.in); got != tc.want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestTerminalNeutralisesHostileFields verifies that the terminal renderer
// strips escapes from every identifier and free-text field, including fields
// that are normally machine-generated (ReportID, RuleID, Evidence.ID) but may
// be hostile when the report is loaded from disk.
func TestTerminalNeutralisesHostileFields(t *testing.T) {
	for _, color := range []bool{false, true} {
		var buf bytes.Buffer
		if err := Terminal(&buf, hostileReport(), TerminalOptions{Color: color, Width: 100}); err != nil {
			t.Fatal(err)
		}
		// With colour enabled the renderer legitimately emits its own SGR
		// sequences, so only assert the absence of injected payloads (clear
		// screen, 8-bit CSI, BEL) rather than all ESC.
		out := buf.String()
		if strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\u009b") || strings.ContainsRune(out, '\x07') {
			t.Fatalf("color=%v: hostile payload survived terminal rendering\n%q", color, out)
		}
		if !color {
			assertNoEscape(t, "terminal/no-color", out)
		}
	}
}

// TestTerminalDeterministicOrdering verifies that the terminal renderer emits
// findings in a stable order regardless of their input order, matching the
// JSON/JSONL/Markdown renderers which call Normalize.
func TestTerminalDeterministicOrdering(t *testing.T) {
	forward := sampleReport()
	backward := sampleReport()
	// Reverse the findings slice of the second report.
	for i, j := 0, len(backward.Findings)-1; i < j; i, j = i+1, j-1 {
		backward.Findings[i], backward.Findings[j] = backward.Findings[j], backward.Findings[i]
	}
	// A single finding is order-insensitive; add a second distinct finding so
	// ordering is observable.
	second := sampleReport().Findings[0]
	second.ID = "finding-0002"
	second.Title = "Another finding"
	second.Severity = models.SeverityLow
	second.Resource = "/tmp/second"
	forward.Findings = append(forward.Findings, second)
	backward.Findings = append([]models.Finding{second}, backward.Findings...)

	render := func(rep models.Report) string {
		var buf bytes.Buffer
		if err := Terminal(&buf, rep, TerminalOptions{Color: false, Width: 100}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	a := render(forward)
	b := render(backward)
	if a != b {
		t.Fatalf("terminal output depends on input finding order\n--- forward ---\n%s\n--- backward ---\n%s", a, b)
	}
}

// TestMarkdownNeutralisesHostileFields verifies markdown output never contains
// raw control bytes and that identifier backticks are escaped so they cannot
// break out of their code spans.
func TestMarkdownNeutralisesHostileFields(t *testing.T) {
	rep := hostileReport()
	// Introduce a backtick into an identifier to exercise code-span escaping.
	rep.Findings[0].RuleID = "NULQ-T-001`evil"
	for i := range rep.Evidence {
		rep.Evidence[i].ID = "ev-`1"
	}
	var buf bytes.Buffer
	if err := Markdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	assertNoEscape(t, "markdown", out)
	if strings.Contains(out, "`evil") {
		t.Fatalf("markdown output contains an unescaped backtick breakout\n%q", out)
	}
}

// TestMachineFormatsEscapeControlBytes verifies JSON, JSONL and SARIF encode
// ESC as a JSON escape sequence rather than emitting the raw byte, so piping
// the output to a terminal is safe.
func TestMachineFormatsEscapeControlBytes(t *testing.T) {
	rep := hostileReport()
	for name, render := range map[string]func(io.Writer, models.Report) error{
		"json":  JSON,
		"jsonl": JSONL,
		"sarif": RenderSARIF,
	} {
		var buf bytes.Buffer
		if err := render(&buf, rep); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := buf.String()
		if strings.ContainsRune(out, '\x1b') {
			t.Fatalf("%s: raw ESC byte present in machine output", name)
		}
		if strings.ContainsRune(out, '\x07') {
			t.Fatalf("%s: raw BEL byte present in machine output", name)
		}
	}
}

// TestMalformedReportRendersWithoutPanic verifies every renderer tolerates a
// structurally degenerate but schema-valid report (nil slices, zero times,
// unknown severity, negative duration) without panicking.
func TestMalformedReportRendersWithoutPanic(t *testing.T) {
	rep := models.Report{
		SchemaVersion: models.SchemaVersion,
		Scan:          models.ScanInfo{DurationMS: -5},
		Findings: []models.Finding{{
			ID:       "finding-x",
			RuleID:   "NULQ-X-000",
			Severity: models.Severity("BOGUS"),
		}},
		// Findings[0].Evidence is nil; the renderer must not panic.
	}
	renderers := map[string]func(io.Writer, models.Report) error{
		"terminal": func(b io.Writer, r models.Report) error {
			return Terminal(b, r, TerminalOptions{Width: 60})
		},
		"system":   func(b io.Writer, r models.Report) error { return SystemInfo(b, r, TerminalOptions{Width: 60}) },
		"json":     JSON,
		"jsonl":    JSONL,
		"markdown": Markdown,
		"sarif":    RenderSARIF,
	}
	for name, render := range renderers {
		var buf bytes.Buffer
		if err := render(&buf, rep); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
