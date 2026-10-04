package reporter

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

// Terminal renders scan results as human-readable colored terminal output.
type Terminal struct {
	Writer io.Writer
	Color  bool // Whether to use ANSI colors
	Quiet  bool // Quiet mode: minimal/compact output
}

// NewTerminal creates a terminal reporter that writes to stdout.
// Color is enabled by default but respects the NO_COLOR environment variable.
func NewTerminal() *Terminal {
	useColor := true
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		useColor = false
	}
	return &Terminal{
		Writer: os.Stdout,
		Color:  useColor,
		Quiet:  false,
	}
}

func (t *Terminal) Report(result *engine.ScanResult) error {
	w := t.Writer

	if t.Quiet {
		// Quiet mode: compact output without banners or descriptions
		for _, f := range result.Findings {
			cleanRuleID := SanitizeOneLine(f.RuleID)
			cleanTitle := SanitizeOneLine(f.Title)
			var loc string
			if f.Path != "" {
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", SanitizeOneLine(f.Path), f.Line)
				} else {
					loc = SanitizeOneLine(f.Path)
				}
			}
			if loc != "" {
				fmt.Fprintf(w, "[%s] [%s] %s %s\n", f.Severity.Label(), cleanRuleID, loc, cleanTitle)
			} else {
				fmt.Fprintf(w, "[%s] [%s] %s\n", f.Severity.Label(), cleanRuleID, cleanTitle)
			}
		}
		for _, e := range result.Errors {
			fmt.Fprintf(w, "[ERROR] [%s] %s\n", SanitizeOneLine(e.CheckID), SanitizeOneLine(e.Err.Error()))
		}
		return nil
	}

	// Header
	t.writeln(w, "")
	t.writeColored(w, colorBold, "HAMMERHEAD SECURITY AUDIT")
	t.writeln(w, "")

	// Repository info
	repoName := SanitizeOneLine(filepath.Base(result.RepoRoot))
	fmt.Fprintf(w, "  Repository:  %s\n", repoName)
	fmt.Fprintf(w, "  Path:        %s\n", SanitizeOneLine(result.RepoRoot))
	fmt.Fprintf(w, "  Checks run:  %d\n", result.ChecksRun)

	if len(result.Findings) == 0 {
		t.writeln(w, "")
		fmt.Fprintf(w, "  Security risk:          ")
		t.writeColored(w, colorGreen, "NONE")
		t.writeln(w, "")
		t.writeln(w, "")
		t.writeColored(w, colorGreen, "  ✓ No findings")
		t.writeln(w, "")
		return nil
	}

	// Risk and classification summary
	classCounts := finding.CountByClass(result.Findings)
	secCount := classCounts[finding.ClassSecurity]
	hygCount := classCounts[finding.ClassHygiene]
	infoCount := classCounts[finding.ClassInfo]

	maxSec, hasSec := finding.MaxSecuritySeverity(result.Findings)

	t.writeln(w, "")
	fmt.Fprintf(w, "  Security risk:          ")
	if hasSec {
		t.writeColored(w, severityColor(maxSec), maxSec.Label())
	} else {
		t.writeColored(w, colorGreen, "NONE")
	}
	t.writeln(w, "")

	fmt.Fprintf(w, "  Security findings:      %d\n", secCount)
	fmt.Fprintf(w, "  Hygiene observations:   %d\n", hygCount)
	fmt.Fprintf(w, "  Informational context:  %d\n", infoCount)

	t.writeln(w, "  ─────────────────────")
	counts := finding.CountBySeverity(result.Findings)
	for _, sev := range finding.AllSeverities() {
		count := counts[sev]
		label := fmt.Sprintf("  %-10s %d", sev.Label(), count)
		if count > 0 {
			t.writeColored(w, severityColor(sev), label)
		} else {
			fmt.Fprint(w, label)
		}
		t.writeln(w, "")
	}
	t.writeln(w, "  ─────────────────────")

	// Helper to render a group of findings
	renderGroup := func(groupTitle string, findings []finding.Finding) {
		if len(findings) == 0 {
			return
		}

		t.writeln(w, "")
		t.writeColored(w, colorBold, fmt.Sprintf("  === %s (%d) ===", groupTitle, len(findings)))
		t.writeln(w, "")

		currentSev := finding.Severity(-1)
		for _, f := range findings {
			if f.Severity != currentSev {
				currentSev = f.Severity
				t.writeln(w, "")
				t.writeColored(w, severityColor(f.Severity), "  "+f.Severity.Label())
				t.writeln(w, "")
			}

			t.writeln(w, "")
			cleanRuleID := SanitizeOneLine(f.RuleID)
			cleanTitle := SanitizeOneLine(f.Title)
			header := fmt.Sprintf("  [%s] %s", cleanRuleID, cleanTitle)
			t.writeColored(w, severityColor(f.Severity), header)
			t.writeln(w, "")

			if f.Path != "" {
				fmt.Fprintf(w, "    Location:     %s", SanitizeOneLine(f.Path))
				if f.Line > 0 {
					fmt.Fprintf(w, ":%d", f.Line)
				}
				t.writeln(w, "")
			}

			if f.Evidence != "" {
				fmt.Fprintf(w, "    Evidence:     %s\n", SanitizeOneLine(f.Evidence))
			}

			fmt.Fprintf(w, "    Confidence:   %s\n", f.Confidence)

			t.writeln(w, "")
			t.writeWrapped(w, "    Why it matters:", SanitizeMultiline(f.Description), 72)
			t.writeln(w, "")
			t.writeWrapped(w, "    Remediation:", SanitizeMultiline(f.Remediation), 72)
		}
	}

	// Partition findings by class (preserve severity ordering within each class)
	var secFindings, hygFindings, infoFindings []finding.Finding
	for _, f := range result.Findings {
		switch f.Class {
		case finding.ClassSecurity:
			secFindings = append(secFindings, f)
		case finding.ClassHygiene:
			hygFindings = append(hygFindings, f)
		case finding.ClassInfo:
			infoFindings = append(infoFindings, f)
		default:
			// Default legacy/unclassified to security
			secFindings = append(secFindings, f)
		}
	}

	renderGroup("SECURITY FINDINGS", secFindings)
	renderGroup("HYGIENE OBSERVATIONS", hygFindings)
	renderGroup("INFORMATIONAL CONTEXT", infoFindings)

	// Check errors
	if len(result.Errors) > 0 {
		t.writeln(w, "")
		t.writeColored(w, colorYellow, "  WARNINGS")
		t.writeln(w, "")
		for _, e := range result.Errors {
			fmt.Fprintf(w, "    • Check %s: %s\n", SanitizeOneLine(e.CheckID), SanitizeOneLine(e.Err.Error()))
		}
	}

	t.writeln(w, "")
	fmt.Fprintf(w, "  %d finding(s) in %d check(s)\n", len(result.Findings), result.ChecksRun)
	t.writeln(w, "")

	return nil
}

// === ANSI color helpers ===
// Minimal set — no external dependency needed.

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorOrange = "\033[38;5;208m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

func (t *Terminal) writeColored(w io.Writer, color, text string) {
	if t.Color {
		fmt.Fprintf(w, "%s%s%s", color, text, colorReset)
	} else {
		fmt.Fprint(w, text)
	}
}

func (t *Terminal) writeln(w io.Writer, text string) {
	fmt.Fprintln(w, text)
}

func (t *Terminal) writeWrapped(w io.Writer, label, text string, width int) {
	fmt.Fprintf(w, "%s\n", label)
	indent := "      "
	words := strings.Fields(text)
	line := indent
	for _, word := range words {
		if len(line)+len(word)+1 > width && line != indent {
			fmt.Fprintln(w, line)
			line = indent
		}
		if line == indent {
			line += word
		} else {
			line += " " + word
		}
	}
	if line != indent {
		fmt.Fprintln(w, line)
	}
}

func severityColor(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return colorBold + colorRed
	case finding.SeverityHigh:
		return colorRed
	case finding.SeverityMedium:
		return colorOrange
	case finding.SeverityLow:
		return colorYellow
	case finding.SeverityInfo:
		return colorCyan
	default:
		return colorGray
	}
}
