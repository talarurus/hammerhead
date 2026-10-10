package reporter

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Presentation limits do not crop stored paths, identities or JSON data.
	MaxTerminalTextBytes = 16 * 1024
	MaxDiagnosticBytes   = 2 * 1024
)

// StripANSI removes CSI, OSC and other terminal escape/control strings,
// including C1 introducers and unterminated strings. The parser is linear and
// does not let embedded newlines escape an OSC/DCS/APC/PM/SOS string.
func StripANSI(s string) string {
	const (
		plain = iota
		escape
		intermediate
		csi
		controlString
		stringEscape
	)
	state := plain
	var b strings.Builder
	for _, r := range s {
		switch state {
		case plain:
			switch r {
			case '\x1b':
				state = escape
			case '\u009b':
				state = csi
			case '\u0090', '\u0098', '\u009d', '\u009e', '\u009f':
				state = controlString
			default:
				b.WriteRune(r)
			}
		case escape:
			switch r {
			case '[':
				state = csi
			case ']', 'P', 'X', '^', '_':
				state = controlString
			default:
				if r >= 0x20 && r <= 0x2f {
					state = intermediate
				} else if r != '\x1b' {
					state = plain
				}
			}
		case intermediate:
			if r >= 0x30 && r <= 0x7e {
				state = plain
			}
		case csi:
			if r >= 0x40 && r <= 0x7e {
				state = plain
			}
		case controlString:
			if r == '\a' || r == '\u009c' {
				state = plain
			} else if r == '\x1b' {
				state = stringEscape
			}
		case stringEscape:
			if r == '\\' || r == '\a' || r == '\u009c' {
				state = plain
			} else if r != '\x1b' {
				state = controlString
			}
		}
	}
	return b.String()
}

// limitText bounds work before escape parsing and marks presentation truncation.
func limitText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	i := limit - len("…")
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "…"
}

// SanitizeOneLine prevents terminal controls and line/header spoofing. Unicode
// format controls (including bidi overrides/isolates) are removed. This is
// presentation sanitization, NOT secret redaction or path privacy.
func SanitizeOneLine(s string) string {
	return sanitize(s, false, MaxTerminalTextBytes)
}

// SanitizeDiagnostic bounds the complete diagnostic line, including its prefix.
func SanitizeDiagnostic(s string) string {
	return sanitize(s, false, MaxDiagnosticBytes)
}

// SanitizeMultiline preserves intentional LF/tab whitespace in reviewed prose.
// Terminal wrapping reflows it; all other controls and Unicode format controls
// are removed. Stored findings and JSON are never modified.
func SanitizeMultiline(s string) string {
	return sanitize(s, true, MaxTerminalTextBytes)
}

func sanitize(s string, multiline bool, limit int) string {
	clean := StripANSI(limitText(s, limit))
	var b strings.Builder
	lastSpace := false
	for _, r := range clean {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		if multiline {
			if r == '\r' || (unicode.IsControl(r) && r != '\n' && r != '\t') {
				continue
			}
		} else if unicode.IsControl(r) || unicode.IsSpace(r) {
			r = ' '
			if lastSpace {
				continue
			}
		}
		// Zl/Zp are line separators even though IsControl does not include them.
		if unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			break
		}
		b.WriteRune(r)
		lastSpace = r == ' '
	}
	if multiline {
		return b.String()
	}
	return strings.TrimSpace(b.String())
}
