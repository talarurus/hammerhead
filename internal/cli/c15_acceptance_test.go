package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/app"
	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Hooks wrap real checks in tests only, after real traversal and before the
// real guarded read. No permission-dependent chmod fixture or production hook.
type gatedCheck struct {
	check.Check
	before func(context.Context)
}

func (c gatedCheck) Run(ctx context.Context, sc *check.ScanContext) error {
	c.before(ctx)
	return c.Check.Run(ctx, sc)
}

func c15Root(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{"README.md": "synthetic", "LICENSE": "synthetic", ".gitignore": ".env\n*.key\nid_*\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func c15Audit(before func(context.Context)) auditFunc {
	return func(ctx context.Context, req app.AuditRequest) (*app.AuditResponse, error) {
		registry := engine.NewRegistry()
		for _, c := range engine.DefaultRegistry().All() {
			if c.Meta().ID == "SEC-001" {
				c = gatedCheck{Check: c, before: before}
			}
			if err := registry.Add(c); err != nil {
				return nil, err
			}
		}
		res, err := engine.New(registry).Scan(ctx, req.TargetDir, nil)
		return &app.AuditResponse{Result: res, Threshold: app.ThresholdPolicy{Disabled: req.FailOnNone, Severity: req.FailOn}}, err
	}
}

type c15Report struct {
	Schema   string           `json:"schema"`
	Status   scanstate.Status `json:"status"`
	Findings []struct {
		RuleID string `json:"rule_id"`
		Path   string `json:"path"`
	} `json:"findings"`
	Coverage scanstate.Coverage `json:"coverage"`
}

func decodeC15(t *testing.T, out *bytes.Buffer) c15Report {
	t.Helper()
	var report c15Report
	d := json.NewDecoder(out)
	if err := d.Decode(&report); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF || report.Schema != "hammerhead/v0.2" {
		t.Fatalf("mixed/incomplete JSON: %v %+v", err, report)
	}
	return report
}

func TestCLI_PartialScanEndToEnd(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, findings := range []bool{false, true} {
		for _, format := range []string{"json", "terminal", "quiet"} {
			t.Run(format+"/findings="+strconvBool(findings), func(t *testing.T) {
				root := c15Root(t)
				if findings {
					if err := os.WriteFile(filepath.Join(root, "a.key"), []byte("synthetic"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				vanished := filepath.Join(root, "z.txt")
				if err := os.WriteFile(vanished, []byte("eligible synthetic text"), 0600); err != nil {
					t.Fatal(err)
				}
				var removal error
				audit := c15Audit(func(context.Context) { removal = os.Remove(vanished) })
				args := []string{"audit", root, "--fail-on", "none"}
				if format == "quiet" {
					args = append(args, "--quiet")
				} else {
					args = append(args, "--output", format)
				}
				var out, diag bytes.Buffer
				if code := runWithAudit(context.Background(), args, &out, &diag, audit); code != 2 || removal != nil {
					t.Fatalf("eligible read failure must override none: code=%d removal=%v", code, removal)
				}
				if format == "json" {
					r := decodeC15(t, &out)
					if r.Status != scanstate.StatusPartial || (len(r.Findings) > 0) != findings {
						t.Fatalf("lost status/findings: %+v", r)
					}
					found := false
					for _, reason := range r.Coverage.Reasons {
						found = found || reason.Code == scanstate.ReasonEligibleReadFailure && reason.Count > 0
					}
					if !found {
						t.Fatalf("eligible failure not accounted: %+v", r.Coverage)
					}
				} else {
					statusStream := out.String()
					if format == "quiet" {
						statusStream = diag.String()
						if !findings && out.Len() != 0 {
							t.Fatal("quiet zero findings leaked status to stdout")
						}
					}
					if !strings.Contains(statusStream, "PARTIAL") || !strings.Contains(statusStream, "Coverage") && !strings.Contains(statusStream, "COVERAGE") {
						t.Fatalf("incomplete status/coverage hidden: %s", statusStream)
					}
					if findings && !strings.Contains(out.String(), "[FILE-001]") {
						t.Fatal("collected finding lost")
					}
				}
			})
		}
	}
}

func strconvBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestCLI_CancelDuringScan(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	root := c15Root(t)
	if err := os.WriteFile(filepath.Join(root, "a.key"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	done := make(chan int, 1)
	var out, diag bytes.Buffer
	audit := c15Audit(func(scanCtx context.Context) {
		close(entered)
		<-scanCtx.Done() // Wait for cancellation of the actual CLI/engine child context.
	})
	go func() {
		done <- runWithAudit(ctx, []string{"audit", root, "--output", "json", "--fail-on", "none"}, &out, &diag, audit)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("scan did not finish during cleanup")
		}
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("check readiness watchdog fired")
	}
	cancel() // Earlier real filename checks have already emitted their findings.
	select {
	case code := <-done:
		if code != 2 {
			t.Fatalf("cancelled none returned %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cooperative cancellation exceeded 2 seconds")
	}
	r := decodeC15(t, &out)
	if r.Status != scanstate.StatusCancelled {
		t.Fatalf("status=%s", r.Status)
	}
	found := false
	for _, f := range r.Findings {
		found = found || f.RuleID == "FILE-001" && f.Path == "a.key"
	}
	if !found {
		t.Fatal("cancellation discarded previously collected native finding")
	}
}

func TestCLI_InvalidResultEnums(t *testing.T) {
	for _, status := range []scanstate.Status{"", "COMPLETED", "unknown", "complete", "completed\n"} {
		var out, diag bytes.Buffer
		if code := runWithAudit(context.Background(), []string{"audit", "--output", "json", "--fail-on", "none"}, &out, &diag, outputAudit(status, false, nil)); code != 2 {
			t.Fatalf("invalid status %q passed: %d", status, code)
		}
		decodeC15(t, &out)
	}
}
