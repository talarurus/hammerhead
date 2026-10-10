package reporter_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/reporter"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

var g11WriteError = errors.New("synthetic output failure")

type g11Writer struct {
	calls, failAt int
	short         bool
}

func (w *g11Writer) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, g11WriteError
	}
	return len(p), nil
}

type g11FlushWriter struct {
	bytes.Buffer
	flushes int
}

func (w *g11FlushWriter) Flush() error {
	w.flushes++
	return g11WriteError
}

func TestOutputWriter_LatchesWriteAndFlushFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		destination := &g11Writer{failAt: 1, short: short}
		w := reporter.NewOutputWriter(destination)
		want := g11WriteError
		if short {
			want = io.ErrShortWrite
		}
		for i := 0; i < 3; i++ {
			if _, err := w.Write([]byte("report")); !errors.Is(err, want) {
				t.Fatalf("Write error = %v, want %v", err, want)
			}
		}
		if !errors.Is(w.Flush(), want) || destination.calls != 1 {
			t.Fatalf("failure not latched: %+v", destination)
		}
	}
	destination := &g11FlushWriter{}
	w := reporter.NewOutputWriter(destination)
	fmt.Fprint(w, "buffered")
	if !errors.Is(w.Flush(), g11WriteError) {
		t.Fatal("flush error was lost")
	}
	if n, err := w.Write([]byte("must not be emitted")); n != 0 || !errors.Is(err, g11WriteError) {
		t.Fatalf("write after failed flush: %d, %v", n, err)
	}
	w.Flush()
	if destination.String() != "buffered" || destination.flushes != 1 {
		t.Fatalf("continued after failure: %+v", destination)
	}
}

func g11Result(status scanstate.Status, mixed bool) *engine.ScanResult {
	r := &engine.ScanResult{Status: status, RepoRoot: "/test/repo", ChecksRun: 7}
	if mixed {
		r.Findings = sampleScanResult().Findings
		r.Findings[0].Line = 2
		r.Findings[0].Description = strings.Repeat("reviewed prose ", 20)
		r.Findings = append(r.Findings,
			finding.Finding{RuleID: "GIT-001", Title: "hygiene", Class: finding.ClassHygiene, Severity: finding.SeverityLow},
			finding.Finding{RuleID: "PROJ-002", Title: "context", Class: finding.ClassInfo, Severity: finding.SeverityInfo},
			finding.Finding{RuleID: "legacy", Title: "legacy", Severity: finding.SeverityMedium, Path: "legacy", Evidence: "synthetic"})
	}
	n, done := 1, true
	r.Coverage.Traversal = scanstate.TraversalCoverage{ExaminedEntries: &n, DiscoveredFiles: &n, DiscoveredDirectories: &n, InventoryComplete: &done, RootListingComplete: &done}
	r.Coverage.Checks = []scanstate.CheckCoverage{{RuleID: "GIT-002", Status: scanstate.CheckStatusUnavailable}}
	r.Coverage.Reasons = []scanstate.Reason{{Code: scanstate.ReasonGitUnavailable, Count: 1}}
	r.Diagnostics = []scanstate.Diagnostic{{Stage: "git", Code: scanstate.ReasonGitUnavailable, RuleID: "GIT-002", SafeMessage: "Git is unavailable", Path: "repo"}, {SafeMessage: "safe diagnostic"}}
	return r
}

func TestTerminal_WriteErrorEveryBranch(t *testing.T) {
	for _, status := range []scanstate.Status{scanstate.StatusCompleted, scanstate.StatusPartial, scanstate.StatusFailed, scanstate.StatusCancelled} {
		for _, mixed := range []bool{false, true} {
			for _, quiet := range []bool{false, true} {
				for _, color := range []bool{false, true} {
					name := fmt.Sprintf("%s/mixed=%t/quiet=%t/color=%t", status, mixed, quiet, color)
					t.Run(name, func(t *testing.T) {
						r := g11Result(status, mixed)
						measureOut, measureErr := &g11Writer{}, &g11Writer{}
						term := reporter.Terminal{Writer: measureOut, DiagnosticWriter: measureErr, Quiet: quiet, Color: color}
						if err := term.Report(r); err != nil {
							t.Fatal(err)
						}
						for _, diagnostic := range []bool{false, true} {
							count := measureOut.calls
							if diagnostic {
								count = measureErr.calls
							}
							for failAt := 1; failAt <= count; failAt++ {
								for _, short := range []bool{false, true} {
									out, diag := &g11Writer{}, &g11Writer{}
									failing := out
									if diagnostic {
										failing = diag
									}
									failing.failAt, failing.short = failAt, short
									term.Writer, term.DiagnosticWriter = out, diag
									want := g11WriteError
									if short {
										want = io.ErrShortWrite
									}
									if err := term.Report(r); !errors.Is(err, want) {
										t.Fatalf("diagnostic=%t write=%d short=%t: %v", diagnostic, failAt, short, err)
									}
									if failing.calls != failAt || (!diagnostic && diag.calls != 0) {
										t.Fatalf("continued emitting after failure: out=%d diag=%d failed=%d", out.calls, diag.calls, failAt)
									}
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestJSON_ShortWrite(t *testing.T) {
	for _, pretty := range []bool{false, true} {
		for _, short := range []bool{false, true} {
			w := &g11Writer{failAt: 1, short: short}
			j := reporter.JSON{Writer: w, Pretty: pretty}
			want := g11WriteError
			if short {
				want = io.ErrShortWrite
			}
			if err := j.Report(g11Result(scanstate.StatusCompleted, true)); !errors.Is(err, want) || w.calls != 1 {
				t.Fatalf("pretty=%t short=%t error=%v calls=%d", pretty, short, err, w.calls)
			}
		}
	}
}

func TestReport_FlushFailures(t *testing.T) {
	for _, format := range []string{"terminal", "quiet-stdout", "quiet-stderr", "json"} {
		t.Run(format, func(t *testing.T) {
			w := bufio.NewWriter(&g11Writer{failAt: 1})
			var rep reporter.Reporter
			if format == "json" {
				rep = &reporter.JSON{Writer: w}
			} else {
				term := &reporter.Terminal{Writer: w, DiagnosticWriter: io.Discard, Quiet: strings.HasPrefix(format, "quiet")}
				if format == "quiet-stderr" {
					term.Writer, term.DiagnosticWriter = io.Discard, w
				}
				rep = term
			}
			if err := rep.Report(g11Result(scanstate.StatusPartial, true)); !errors.Is(err, g11WriteError) {
				t.Fatalf("flush failure lost: %v", err)
			}
		})
	}
}

func TestTerminal_ZeroFindingsStatusCoverage(t *testing.T) {
	for _, status := range []scanstate.Status{scanstate.StatusCompleted, scanstate.StatusPartial, scanstate.StatusFailed, scanstate.StatusCancelled} {
		for _, quiet := range []bool{false, true} {
			var out, diag bytes.Buffer
			term := reporter.Terminal{Writer: &out, DiagnosticWriter: &diag, Quiet: quiet}
			if err := term.Report(g11Result(status, false)); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if quiet {
				text = diag.String()
				if out.Len() != 0 {
					t.Fatal("zero-findings quiet stdout is not empty")
				}
			}
			for _, want := range []string{strings.ToUpper(string(status)), "Coverage:", "Inventory complete:", "Findings retained:", "Reason git_unavailable", "Git is unavailable"} {
				if !strings.Contains(text, want) {
					t.Fatalf("status=%s quiet=%t missing %q: %s", status, quiet, want, text)
				}
			}
			if status != scanstate.StatusCompleted && strings.Contains(text, "✓ No findings") {
				t.Fatal("incomplete scan claims no findings success")
			}
			if !quiet && strings.Index(text, "Coverage:") > strings.Index(text, "findings") {
				t.Fatal("coverage appears after empty-findings message")
			}
		}
	}
}

func TestTerminal_DiagnosticsBounded(t *testing.T) {
	r := g11Result(scanstate.StatusPartial, false)
	r.Diagnostics = make([]scanstate.Diagnostic, 205)
	for i := range r.Diagnostics {
		r.Diagnostics[i] = scanstate.Diagnostic{RuleID: strings.Repeat("r", 4000), Path: strings.Repeat("p", 20000), SafeMessage: strings.Repeat("é", 4000)}
	}
	var out, diag bytes.Buffer
	term := reporter.Terminal{Writer: &out, DiagnosticWriter: &diag, Quiet: true}
	if err := term.Report(r); err != nil {
		t.Fatal(err)
	}
	if strings.Count(diag.String(), "[DIAGNOSTIC]") != 200 || !strings.Contains(diag.String(), "omitted from terminal: 5") {
		t.Fatal("diagnostic sample bound or omitted count lost")
	}
	for _, line := range strings.Split(diag.String(), "\n") {
		if len(line) > reporter.MaxDiagnosticBytes || !utf8.ValidString(line) {
			t.Fatalf("unbounded/invalid diagnostic line: %d bytes", len(line))
		}
	}
	if len(r.Diagnostics[0].SafeMessage) != 8000 {
		t.Fatal("presentation modified source diagnostic")
	}
}

type g11WriteFunc func([]byte) (int, error)

func (f g11WriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestJSON_ZeroAndPartialWrites(t *testing.T) {
	for _, fraction := range []int{0, 1, 2} {
		calls := 0
		w := g11WriteFunc(func(p []byte) (int, error) {
			calls++
			return len(p) * fraction / 3, nil
		})
		if err := (&reporter.JSON{Writer: w}).Report(g11Result(scanstate.StatusCompleted, false)); !errors.Is(err, io.ErrShortWrite) || calls != 1 {
			t.Fatalf("fraction=%d error=%v writes=%d", fraction, err, calls)
		}
	}
	w := reporter.NewOutputWriter(g11WriteFunc(func(p []byte) (int, error) { return len(p), g11WriteError }))
	if _, err := w.Write([]byte("complete bytes but reported error")); !errors.Is(err, g11WriteError) {
		t.Fatalf("full-count error was lost: %v", err)
	}
}
