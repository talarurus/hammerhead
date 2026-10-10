package reporter_test

import (
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/reporter"
)

func TestStripANSI(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain text",
			input:    "normal filename.txt",
			expected: "normal filename.txt",
		},
		{
			name:     "CSI color code",
			input:    "\x1b[31;1mCRITICAL_FILE\x1b[0m",
			expected: "CRITICAL_FILE",
		},
		{
			name:     "multiple color codes and resets",
			input:    "\x1b[32mPASS\x1b[0m - \x1b[31mFAIL\x1b[0m",
			expected: "PASS - FAIL",
		},
		{
			name:     "OSC title change sequence",
			input:    "safe\x1b]0;hacked_title\x07name.txt",
			expected: "safename.txt",
		},
		{
			name:     "cursor movement sequence",
			input:    "file\x1b[2K\x1b[1Aoverwritten.txt",
			expected: "fileoverwritten.txt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reporter.StripANSI(tc.input)
			if got != tc.expected {
				t.Errorf("StripANSI(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSanitizeOneLine(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "embedded newlines trying to spoof headers",
			input:    "file.txt\nCRITICAL\n[FAKE-001] Injected vulnerability",
			expected: "file.txt CRITICAL [FAKE-001] Injected vulnerability",
		},
		{
			name:     "carriage return trying to overwrite terminal line",
			input:    "harmless_name.txt\r[CRITICAL] Overwrite",
			expected: "harmless_name.txt [CRITICAL] Overwrite",
		},
		{
			name:     "ANSI escape combined with newline",
			input:    "\x1b[31m\x1b[1mmalicious\x1b[0m\nfake_finding",
			expected: "malicious fake_finding",
		},
		{
			name:     "null bytes and bell characters",
			input:    "bad\x00file\a\bname.txt",
			expected: "bad file name.txt",
		},
		{
			name:     "tabs collapsed",
			input:    "col1\t\t\tcol2",
			expected: "col1 col2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reporter.SanitizeOneLine(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeOneLine(%q) = %q, want %q", tc.input, got, tc.expected)
			}
			// Verify invariants
			if strings.Contains(got, "\n") {
				t.Errorf("SanitizeOneLine output contains newline: %q", got)
			}
			if strings.Contains(got, "\r") {
				t.Errorf("SanitizeOneLine output contains carriage return: %q", got)
			}
			if strings.Contains(got, "\x1b") {
				t.Errorf("SanitizeOneLine output contains escape character: %q", got)
			}
		})
	}
}

func TestSanitizeMultiline(t *testing.T) {
	input := "Line 1\x1b[31m with color\x1b[0m\r\nLine 2 with \x00control chars\nLine 3"
	expected := "Line 1 with color\nLine 2 with control chars\nLine 3"

	got := reporter.SanitizeMultiline(input)
	if got != expected {
		t.Errorf("SanitizeMultiline got %q, want %q", got, expected)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("SanitizeMultiline contains escape char: %q", got)
	}
	if strings.Contains(got, "\r") {
		t.Errorf("SanitizeMultiline contains carriage return: %q", got)
	}
}
