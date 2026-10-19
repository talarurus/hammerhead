package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode"

	"github.com/talarurus/hammerhead/internal/app"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/reporter"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

type cliBrokenWriter struct {
	calls int
	short bool
}

func (w *cliBrokenWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("WRITER_SECRET\x1b]52;c;OSC_PAYLOAD\a\n\u202e")
}

func outputAudit(status scanstate.Status, hasFinding bool, runErr error) auditFunc {
	return func(ctx context.Context, req app.AuditRequest) (*app.AuditResponse, error) {
		r := &engine.ScanResult{Status: status, RepoRoot: "/synthetic/repo"}
		if hasFinding {
			r.Findings = []finding.Finding{{ID: "stable-id", RuleID: "FILE-001", Class: finding.ClassSecurity, Severity: finding.SeverityHigh, Title: "Potential key", Path: "id_rsa"}}
		}
		r.Diagnostics = []scanstate.Diagnostic{{Stage: "git", Code: scanstate.ReasonGitUnavailable, SafeMessage: "Git unavailable"}}
		return &app.AuditResponse{Result: r, Threshold: app.ThresholdPolicy{Severity: req.FailOn, Disabled: req.FailOnNone}}, runErr
	}
}

func TestCLI_ReportFailureExit2(t *testing.T) {
	for _, status := range []scanstate.Status{scanstate.StatusCompleted, scanstate.StatusPartial, scanstate.StatusFailed, scanstate.StatusCancelled} {
		for _, format := range []string{"terminal", "json", "quiet"} {
			for _, hasFinding := range []bool{false, true} {
				for _, threshold := range []string{"high", "none"} {
					for _, short := range []bool{false, true} {
						name := fmt.Sprintf("%s/%s/finding=%t/%s/short=%t", status, format, hasFinding, threshold, short)
						t.Run(name, func(t *testing.T) {
							w := &cliBrokenWriter{short: short}
							var diag bytes.Buffer
							args := []string{"audit", "--fail-on", threshold}
							if format == "quiet" {
								args = append(args, "--quiet")
							} else {
								args = append(args, "--output", format)
							}
							var stdout, stderr io.Writer = w, &diag
							// Quiet zero-findings has no stdout write; fail its required
							// operational diagnostic stream instead.
							if format == "quiet" && !hasFinding {
								stdout, stderr = io.Discard, w
							}
							code := runWithAudit(context.Background(), args, stdout, stderr, outputAudit(status, hasFinding, nil))
							if code != 2 || w.calls != 1 {
								t.Fatalf("code=%d physical writes=%d", code, w.calls)
							}
							if strings.Contains(diag.String(), "WRITER_SECRET") || strings.Contains(diag.String(), "OSC_PAYLOAD") {
								t.Fatal("arbitrary writer error was disclosed")
							}
						})
					}
				}
			}
		}
	}
}

func TestCLI_JSONStreamsSeparated(t *testing.T) {
	for _, status := range []scanstate.Status{scanstate.StatusCompleted, scanstate.StatusPartial, scanstate.StatusFailed, scanstate.StatusCancelled} {
		for _, hasFinding := range []bool{false, true} {
			for _, withError := range []bool{false, true} {
				var out, diag bytes.Buffer
				var runErr error
				if withError {
					runErr = errors.New("RAW_GIT_STDERR_SECRET\x1b]52;c;PAYLOAD\a\n\u202e")
				}
				code := runWithAudit(context.Background(), []string{"audit", "--output", "json"}, &out, &diag, outputAudit(status, hasFinding, runErr))
				want := 2
				if status == scanstate.StatusCompleted && !withError {
					want = 0
					if hasFinding {
						want = 1
					}
				}
				if code != want {
					t.Fatalf("%s finding=%t error=%t code=%d want=%d", status, hasFinding, withError, code, want)
				}
				decoder := json.NewDecoder(&out)
				var report map[string]any
				if err := decoder.Decode(&report); err != nil {
					t.Fatal(err)
				}
				if report["schema"] != "hammerhead-core/v0.2" || report["status"] != string(status) || report["coverage"] == nil {
					t.Fatalf("missing schema/status/coverage: %v", report)
				}
				var extra any
				if err := decoder.Decode(&extra); err != io.EOF {
					t.Fatalf("stdout is not exactly one JSON document: %v", err)
				}
				if want == 2 && diag.Len() == 0 {
					t.Fatal("operational error missing from stderr")
				}
				if want != 2 && diag.Len() != 0 {
					t.Fatalf("ordinary threshold produced stderr error: %q", diag.String())
				}
				if strings.Contains(diag.String(), "RAW_GIT_STDERR_SECRET") {
					t.Fatal("raw service/Git error was disclosed")
				}
			}
		}
	}
}

func TestCLI_VersionHelpWriterFailures(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"audit", "--help"}, {"help", "audit"}, {}} {
		for _, short := range []bool{false, true} {
			var diag bytes.Buffer
			w := &cliBrokenWriter{short: short}
			if code := Run(context.Background(), args, w, &diag); code != 2 || w.calls != 1 {
				t.Fatalf("%v short=%t code=%d writes=%d", args, short, code, w.calls)
			}
			if !strings.Contains(diag.String(), "writing output failed") || strings.Contains(diag.String(), "WRITER_SECRET") {
				t.Fatalf("unsafe/missing error diagnostic: %q", diag.String())
			}
		}
	}
}

func TestCLI_FailingStderrAndFlush(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"audit", "--output", "invalid"}, {"audit", "--quiet"}, {"help", "unknown"}} {
		for _, short := range []bool{false, true} {
			w := &cliBrokenWriter{short: short}
			if code := runWithAudit(context.Background(), args, io.Discard, w, outputAudit(scanstate.StatusCompleted, true, nil)); code != 2 || w.calls != 1 {
				t.Fatalf("%v short=%t code=%d writes=%d", args, short, code, w.calls)
			}
		}
	}
	for _, args := range [][]string{{"version"}, {"--help"}, {"audit", "--output", "json"}, {"audit"}, {"audit", "--quiet"}} {
		w := bufio.NewWriterSize(&cliBrokenWriter{}, 65536)
		var diag bytes.Buffer
		if code := runWithAudit(context.Background(), args, w, &diag, outputAudit(scanstate.StatusCompleted, true, nil)); code != 2 {
			t.Fatalf("stdout flush failure for %v returned %d", args, code)
		}
	}
	w := bufio.NewWriterSize(&cliBrokenWriter{}, 65536)
	if code := Run(context.Background(), []string{"unknown"}, io.Discard, w); code != 2 {
		t.Fatalf("stderr flush failure returned %d", code)
	}
}

func TestCLI_QuietZeroFindingsPartialStreams(t *testing.T) {
	var out, diag bytes.Buffer
	code := runWithAudit(context.Background(), []string{"audit", "--quiet", "--fail-on", "none"}, &out, &diag, outputAudit(scanstate.StatusPartial, false, nil))
	if code != 2 || out.Len() != 0 {
		t.Fatalf("code=%d stdout=%q", code, out.String())
	}
	for _, want := range []string{"[STATUS] PARTIAL", "[COVERAGE]", "Git unavailable"} {
		if !strings.Contains(diag.String(), want) {
			t.Fatalf("missing quiet operational %q: %s", want, diag.String())
		}
	}
}

func TestCLI_MaliciousErrorText(t *testing.T) {
	text := "bad\x1b[31m\x1b]52;c;OSC_PAYLOAD\nMORE\a\r\nspoof\u202e\u2066"
	for _, args := range [][]string{{text}, {"audit", "--output", text}, {"audit", "--fail-on", text}, {"help", text}} {
		var out, diag bytes.Buffer
		if code := Run(context.Background(), args, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), diag.String())
		}
		for _, r := range diag.String() {
			if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) {
				t.Fatalf("unsafe CLI diagnostic: %q", diag.String())
			}
		}
		if strings.Count(diag.String(), "\n") != 1 || len(diag.String()) > reporter.MaxDiagnosticBytes+1 {
			t.Fatalf("unbounded/multiline CLI error: %q", diag.String())
		}
	}
	for _, hasResult := range []bool{false, true} {
		var out, diag bytes.Buffer
		audit := outputAudit(scanstate.StatusPartial, true, errors.New(text+"RAW_SERVICE_SECRET"))
		if !hasResult {
			audit = func(context.Context, app.AuditRequest) (*app.AuditResponse, error) {
				return nil, errors.New(text + "RAW_SERVICE_SECRET")
			}
		}
		if code := runWithAudit(context.Background(), []string{"audit", "--output", "json"}, &out, &diag, audit); code != 2 || strings.Contains(diag.String(), "RAW_SERVICE_SECRET") {
			t.Fatalf("unsafe service error: code=%d stderr=%q", code, diag.String())
		}
	}
}

func TestCLI_VersionMetadataSanitized(t *testing.T) {
	version, commit := Version, Commit
	defer func() { Version, Commit = version, commit }()
	Version = "v\x1b]52;c;OSC_PAYLOAD\a\r\nspoof\u202e"
	Commit = "c\x1b[31m\u2066"
	var out, diag bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &out, &diag); code != 0 || diag.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, diag.String())
	}
	if got := out.String(); got != "Hammerhead Core version v spoof (source base: c)\nCore only: six native checks. GIT-002: NOT EVALUATED (Git health and metadata collection are omitted).\n" {
		t.Fatalf("unsafe version metadata: %q", got)
	}
}
