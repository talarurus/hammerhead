package reporter_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/reporter"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

func assertTerminalSafe(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			t.Fatalf("terminal control U+%04X survived: %q", r, s)
		}
	}
}

func TestSanitize_TerminalControlsAndBounds(t *testing.T) {
	for i, tc := range []struct{ in, want string }{
		{"before\x1b]52;c;OSC_PAYLOAD\nSTILL_PAYLOAD\aafter", "beforeafter"},
		{"before\x1b]8;;OSC_PAYLOAD\x1b\\after", "beforeafter"},
		{"before\x1bPDEVICE_PAYLOAD\nMORE\x1b\\after", "beforeafter"},
		{"before\x1b_UNTRUSTED\x1b\\after", "beforeafter"},
		{"before\u009dOSC_PAYLOAD\u009cafter", "beforeafter"},
		{"before\u009b31mafter", "beforeafter"},
		{"before\x1b[?25lafter", "beforeafter"},
		{"before\x1b(Bafter", "beforeafter"},
		{"before\x1b]UNTERMINATED\nPAYLOAD", "before"},
		{"before\x1b[123", "before"},
		{"a\u202eb\u2066c\u2069d\u200de\ufefff", "abcdef"},
		{"a\r\nb\u2028c\u2029d\x00e", "a b c d e"},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := reporter.SanitizeOneLine(tc.in)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			assertTerminalSafe(t, got)
		})
	}
	for _, input := range []string{strings.Repeat("é", 20000), strings.Repeat("\xff", 20000), strings.Repeat("\x1b]unterminated", 2000)} {
		for _, sanitize := range []func(string) string{reporter.SanitizeOneLine, reporter.SanitizeMultiline, reporter.SanitizeDiagnostic} {
			got := sanitize(input)
			if !utf8.ValidString(got) || len(got) > reporter.MaxTerminalTextBytes {
				t.Fatalf("invalid or unbounded output: %d", len(got))
			}
			assertTerminalSafe(t, got)
		}
		if got := reporter.SanitizeDiagnostic(input); len(got) > reporter.MaxDiagnosticBytes {
			t.Fatal("diagnostic bound exceeded")
		}
	}
}

func TestTerminal_MaliciousTextPreservesJSON(t *testing.T) {
	text := "safe\x1b[31m\x1b]52;c;OSC_PAYLOAD\nMORE\x1b\\\r\nspoof\u202e\u2066.key"
	r := g11Result(scanstate.StatusPartial, true)
	r.RepoRoot = text
	f := &r.Findings[0]
	f.ID, f.RuleID, f.Path, f.Title, f.Evidence = text, text, text, text, text
	f.Description, f.Remediation = text, text
	r.Diagnostics[0].RuleID, r.Diagnostics[0].Path, r.Diagnostics[0].SafeMessage = text, text, text
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, quiet := range []bool{false, true} {
		var out, diag bytes.Buffer
		term := reporter.Terminal{Writer: &out, DiagnosticWriter: &diag, Quiet: quiet}
		if err := term.Report(r); err != nil {
			t.Fatal(err)
		}
		for _, stream := range []string{out.String(), diag.String()} {
			assertTerminalSafe(t, stream)
			if strings.Contains(stream, "OSC_PAYLOAD") || strings.Contains(stream, "MORE") || strings.Contains(stream, "\nspoof") {
				t.Fatalf("control string or spoofed line survived: %q", stream)
			}
		}
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("terminal rendering changed stored finding/diagnostic identity or text")
	}
	var out bytes.Buffer
	j := reporter.JSON{Writer: &out}
	if err := j.Report(r); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Findings    []finding.Finding      `json:"findings"`
		Diagnostics []scanstate.Diagnostic `json:"diagnostics"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Findings[0].ID != text || parsed.Findings[0].Path != text || parsed.Diagnostics[0].SafeMessage != text {
		t.Fatal("terminal sanitization altered the JSON representation")
	}
}
