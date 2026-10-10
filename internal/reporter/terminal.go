package reporter

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Terminal renders scan results as human-readable colored terminal output.
type Terminal struct {
	Writer           io.Writer
	DiagnosticWriter io.Writer // Quiet operational status; defaults to stderr, never stdout.
	Color            bool      // Whether to use ANSI colors
	Quiet            bool      // Quiet mode: minimal/compact output
}

// NewTerminal creates a terminal reporter that writes to stdout.
// Color is enabled by default but respects the NO_COLOR environment variable.
func NewTerminal() *Terminal {
	useColor := true
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		useColor = false
	}
	return &Terminal{
		Writer:           os.Stdout,
		DiagnosticWriter: os.Stderr,
		Color:            useColor,
		Quiet:            false,
	}
}

func (t *Terminal) Report(result *engine.ScanResult) error {
	w := NewOutputWriter(t.Writer)
	if t.Quiet {
		return t.reportQuiet(w, result)
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

	// Completion and coverage precede any empty-findings message.
	t.writeOperational(w, result, false)
	if w.Err() != nil {
		return w.Err()
	}
	printDiagnostics := func() { t.writeDiagnostics(w, result, false) }

	if len(result.Findings) == 0 {
		t.writeln(w, "")
		fmt.Fprintf(w, "  Security risk:          ")

		if string(result.Status) == "completed" {
			t.writeColored(w, colorGreen, "NONE")
			t.writeln(w, "")
			t.writeln(w, "")
			t.writeColored(w, colorGreen, "  ✓ No findings")
			printDiagnostics()
		} else {
			t.writeColored(w, colorYellow, "UNKNOWN")
			t.writeln(w, "")
			t.writeln(w, "")
			t.writeColored(w, colorYellow, fmt.Sprintf("  ⚠ Scan %s with no findings", SanitizeOneLine(string(result.Status))))
			printDiagnostics()
		}
		t.writeln(w, "")
		return w.Flush()
	}

	// Risk and classification summary
	classCounts := finding.CountByClass(result.Findings)
	secCount := classCounts[finding.ClassSecurity]
	hygCount := classCounts[finding.ClassHygiene]
	infoCount := classCounts[finding.ClassInfo]

	maxSec, hasSec := result.HighestObservedSecuritySeverity()

	t.writeln(w, "")
	fmt.Fprintf(w, "  Security risk:          ")
	if hasSec {
		t.writeColored(w, severityColor(maxSec), maxSec.Label())
	} else if string(result.Status) == "completed" {
		t.writeColored(w, colorGreen, "NONE")
	} else {
		t.writeColored(w, colorYellow, "UNKNOWN")
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
		if len(findings) == 0 || w.Err() != nil {
			return
		}

		t.writeln(w, "")
		t.writeColored(w, colorBold, fmt.Sprintf("  === %s (%d) ===", groupTitle, len(findings)))
		t.writeln(w, "")

		currentSev := finding.Severity(-1)
		for _, f := range findings {
			if w.Err() != nil {
				return
			}
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

			fmt.Fprintf(w, "    Confidence:   %s\n", f.Confidence.String())

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

	printDiagnostics()

	t.writeln(w, "")
	fmt.Fprintf(w, "  %d finding(s) in %d check(s)\n", len(result.Findings), result.ChecksRun)
	t.writeln(w, "")

	return w.Flush()
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

func (t *Terminal) reportQuiet(w *OutputWriter, result *engine.ScanResult) error {
	for _, f := range result.Findings {
		if w.Err() != nil {
			break
		}
		loc := SanitizeOneLine(f.Path)
		if loc != "" && f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		if loc != "" {
			fmt.Fprintf(w, "[%s] [%s] %s %s\n", f.Severity.Label(), SanitizeOneLine(f.RuleID), loc, SanitizeOneLine(f.Title))
		} else {
			fmt.Fprintf(w, "[%s] [%s] %s\n", f.Severity.Label(), SanitizeOneLine(f.RuleID), SanitizeOneLine(f.Title))
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	destination := t.DiagnosticWriter
	if destination == nil {
		destination = os.Stderr
	}
	dw := NewOutputWriter(destination)
	t.writeOperational(dw, result, true)
	t.writeDiagnostics(dw, result, true)
	return dw.Flush()
}

func (t *Terminal) writeOperational(w *OutputWriter, result *engine.ScanResult, quiet bool) {
	prefix := "  "
	if quiet {
		prefix = "[COVERAGE] "
		fmt.Fprintln(w, SanitizeDiagnostic("[STATUS] "+strings.ToUpper(SanitizeDiagnostic(string(result.Status)))))
	} else {
		fmt.Fprintln(w, SanitizeDiagnostic("  Status: "+strings.ToUpper(SanitizeDiagnostic(string(result.Status)))))
	}
	v := result.Coverage.Traversal
	fmt.Fprintf(w, "%sCoverage: examined %s entries; files %s; directories %s\n", prefix, knownInt(v.ExaminedEntries), knownInt(v.DiscoveredFiles), knownInt(v.DiscoveredDirectories))
	fmt.Fprintf(w, "%sInventory complete: %s; root listing complete: %s\n", prefix, knownBool(v.InventoryComplete), knownBool(v.RootListingComplete))
	fmt.Fprintf(w, "%sFindings retained: %d; truncated: %t; diagnostic examples omitted: %s\n", prefix, result.Coverage.FindingsRetained, result.Coverage.FindingsTruncated, knownInt(result.Coverage.DiagnosticExamplesOmitted))
	fmt.Fprintf(w, "%sPolicy: %d exclusions; %d applied limits\n", prefix, len(result.Coverage.Policy.Exclusions), len(result.Coverage.Policy.EffectiveLimits))
	limit := scanstate.ProductionLimits().MaxDiagnosticSamples
	for i, check := range result.Coverage.Checks {
		if i >= limit || w.Err() != nil {
			break
		}
		line := fmt.Sprintf("%sCheck [%s]: %s; eligible %s; inspected %s; read bytes %s", prefix, SanitizeDiagnostic(check.RuleID), SanitizeDiagnostic(string(check.Status)), knownInt(check.EligibleFiles), knownInt(check.InspectedFiles), knownInt(check.ReadBytes))
		fmt.Fprintln(w, SanitizeDiagnostic(line))
	}
	for i, reason := range result.Coverage.Reasons {
		if i >= limit || w.Err() != nil {
			break
		}
		fmt.Fprintln(w, SanitizeDiagnostic(fmt.Sprintf("%sReason %s: %d; lower bound: %t", prefix, SanitizeDiagnostic(string(reason.Code)), reason.Count, reason.CountIsLowerBound)))
	}
}

func (t *Terminal) writeDiagnostics(w *OutputWriter, result *engine.ScanResult, quiet bool) {
	if len(result.Diagnostics) == 0 || w.Err() != nil {
		return
	}
	if !quiet {
		t.writeln(w, "")
		t.writeColored(w, colorYellow, "  DIAGNOSTICS")
		t.writeln(w, "")
	}
	limit := scanstate.ProductionLimits().MaxDiagnosticSamples
	for i, d := range result.Diagnostics {
		if i >= limit || w.Err() != nil {
			break
		}
		prefix := "    • "
		if quiet {
			prefix = "[DIAGNOSTIC] "
		}
		if d.RuleID != "" {
			prefix += "[" + SanitizeDiagnostic(d.RuleID) + "] "
		}
		line := prefix + SanitizeDiagnostic(d.SafeMessage)
		if d.Path != "" {
			line += " (path: " + SanitizeDiagnostic(d.Path) + ")"
		}
		fmt.Fprintln(w, SanitizeDiagnostic(line))
	}
	if len(result.Diagnostics) > limit && w.Err() == nil {
		fmt.Fprintf(w, "  Diagnostic samples omitted from terminal: %d\n", len(result.Diagnostics)-limit)
	}
}

func knownInt(v *int) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprint(*v)
}

func knownBool(v *bool) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprint(*v)
}
