package reporting

import "strings"

// Control characters in paths, group names and configuration values can be
// used for terminal escape injection. Every value that originates from the
// assessed system passes through these helpers before it reaches a terminal
// or a Markdown document.

// SanitizeLine removes C0 and C1 control characters and folds newlines and
// tabs into spaces. It is the exported counterpart of singleLine for callers
// outside this package that must render a value originating outside the process
// (for example a field read back from a stored report) without allowing
// terminal escape injection. See AGENTS.md §2.8 and §13.
func SanitizeLine(value string) string { return singleLine(value) }

// singleLine removes C0 and C1 control characters, folding newlines and tabs
// into spaces.
func singleLine(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		case r >= 0x80 && r < 0xa0:
			return -1
		}
		return r
	}, value)
}

// multiLine preserves line breaks but removes every other control character,
// including ESC, so an observation cannot rewrite the terminal.
func multiLine(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f:
			return -1
		case r >= 0x80 && r < 0xa0:
			return -1
		}
		return r
	}, value)
}

// markdownSafe escapes table separators while preserving readable prose.
func markdownSafe(value string) string {
	cleaned := strings.ReplaceAll(singleLine(value), "|", "\\|")
	return strings.ReplaceAll(cleaned, "`", "'")
}
