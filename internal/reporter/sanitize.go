package reporter

import (
	"regexp"
	"strings"
	"unicode"
)

// ansiRegex matches ANSI escape sequences:
//   - CSI sequences: \x1b\[[0-9;?]*[a-zA-Z]
//   - OSC sequences: \x1b\][^\x07\x1b]*(\x07|\x1b\\)
//   - Fe sequences: \x1b[@-Z\\-_]
var ansiRegex = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[a-zA-Z]|\].*?(?:\x07|\x1b\\)|[@-Z\\-_])`)

// StripANSI removes all ANSI escape sequences from a string.
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// SanitizeOneLine sanitizes a string intended to be printed on a single terminal line
// (such as filenames, paths, evidence snippets, and labels).
//
// It guarantees that:
//  1. No ANSI escape sequences remain to alter colors, cursor position, or execute commands.
//  2. No newlines (\r, \n) or tabs remain to spoof additional findings or split lines.
//  3. No unprintable or ASCII control characters (< 0x20, 0x7f) remain.
//
// Multiple consecutive spaces resulting from newline/control replacement are collapsed.
func SanitizeOneLine(s string) string {
	// 1. Remove ANSI escape sequences
	clean := StripANSI(s)

	// 2. Replace control characters and newlines with space
	var b strings.Builder
	b.Grow(len(clean))

	lastWasSpace := false
	for _, r := range clean {
		if r == '\r' || r == '\n' || r == '\t' || unicode.IsControl(r) {
			if !lastWasSpace {
				b.WriteByte(' ')
				lastWasSpace = true
			}
			continue
		}
		b.WriteRune(r)
		lastWasSpace = (r == ' ')
	}

	return strings.TrimSpace(b.String())
}

// SanitizeMultiline sanitizes multi-line descriptive text (such as descriptions and
// remediation guidance) before terminal printing.
//
// It strips ANSI escapes and dangerous control characters, while preserving
// intentional newline paragraph breaks (\n).
func SanitizeMultiline(s string) string {
	clean := StripANSI(s)

	var b strings.Builder
	b.Grow(len(clean))

	for _, r := range clean {
		if r == '\r' {
			continue // normalize CRLF to LF
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue // drop all other control characters
		}
		b.WriteRune(r)
	}

	return b.String()
}
