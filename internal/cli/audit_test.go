package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/app"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func TestCLI_InvalidOptionsDoNotScan(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"invalid format", []string{"audit", "--output", "xml"}},
		{"invalid fail-on", []string{"audit", "--fail-on", "super"}},
		{"invalid max-size", []string{"audit", "--max-file-size", "100gigabytes"}},
		{"invalid glob", []string{"audit", "--exclude", "["}},
		{"too many args", []string{"audit", ".", "extra-arg"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invocations := 0
			fakeAudit := func(ctx context.Context, req app.AuditRequest) (*app.AuditResponse, error) {
				invocations++
				return nil, nil
			}

			var stdout, stderr bytes.Buffer
			code := runWithAudit(context.Background(), tt.args, &stdout, &stderr, fakeAudit)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if invocations != 0 {
				t.Errorf("expected ZERO audit invocation for %s", tt.name)
			}
		})
	}
}

func TestCLI_RepeatedInvocationsIsolated(t *testing.T) {
	var requests []app.AuditRequest

	fakeAudit := func(ctx context.Context, req app.AuditRequest) (*app.AuditResponse, error) {
		requests = append(requests, req)
		res := &engine.ScanResult{
			Status: scanstate.StatusCompleted,
			Findings: []finding.Finding{
				{ID: "finding-123", Severity: finding.SeverityHigh, Class: finding.ClassSecurity},
			},
		}
		res.RecordObservedSecurity(finding.SeverityHigh)
		return &app.AuditResponse{
			Result:    res,
			Threshold: app.ThresholdPolicy{Disabled: req.FailOnNone, Severity: req.FailOn},
		}, nil
	}

	var stdoutA, stderrA bytes.Buffer

	// Invocation 1: json, explicit options
	codeA := runWithAudit(context.Background(), []string{"audit", ".", "--fail-on", "info", "--exclude", "first-pattern", "--max-file-size", "10MB", "--output", "json"}, &stdoutA, &stderrA, fakeAudit)
	if codeA != 1 { // Should exit 1 because finding is high and threshold is info
		t.Fatalf("first invocation failed setup (code %d)", codeA)
	}

	var stdoutB, stderrB bytes.Buffer
	// Invocation 2: terminal (default), quiet, different options
	codeB := runWithAudit(context.Background(), []string{"audit", ".", "--fail-on", "critical", "--quiet"}, &stdoutB, &stderrB, fakeAudit)
	if codeB != 0 { // Should exit 0 because finding is high and threshold is critical
		t.Fatalf("second invocation failed setup (code %d)", codeB)
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}

	// Validate Invocation A Output (JSON)
	outA := stdoutA.String()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(outA), &parsed); err != nil {
		t.Errorf("Invocation A expected JSON, but failed to parse: %v", err)
	}

	// Validate Invocation B Output (Terminal + Quiet)
	outB := stdoutB.String()
	if json.Unmarshal([]byte(outB), &parsed) == nil {
		t.Errorf("Invocation B should NOT be JSON, but parsed successfully")
	}
	// With quiet terminal reporter, we expect just findings list or no banners.
	// Since we don't have exact quiet semantics, we at least know it shouldn't contain JSON structure.

	reqA := requests[0]
	if reqA.FailOn != finding.SeverityInfo {
		t.Errorf("Invocation A: expected FailOn info, got %v", reqA.FailOn)
	}

	reqB := requests[1]
	if reqB.FailOn != finding.SeverityCritical {
		t.Errorf("expected FailOn critical, got %v", reqB.FailOn)
	}
	if len(reqB.ExcludePatterns) != 0 {
		t.Errorf("expected 0 exclude patterns, got %v", reqB.ExcludePatterns)
	}
	if reqB.MaxFileSize != 0 {
		t.Errorf("expected default max file size (0), got %v", reqB.MaxFileSize)
	}
	if reqB.FailOnNone != false {
		t.Errorf("expected FailOnNone false, got true")
	}
}

func TestCLI_FindingExitOneDoesNotPrintError(t *testing.T) {
	fakeAudit := func(ctx context.Context, req app.AuditRequest) (*app.AuditResponse, error) {
		res := &engine.ScanResult{
			Status: scanstate.StatusCompleted,
			Findings: []finding.Finding{
				{Severity: finding.SeverityHigh, Class: finding.ClassSecurity},
			},
		}
		res.RecordObservedSecurity(finding.SeverityHigh)
		return &app.AuditResponse{
			Result:    res,
			Threshold: app.ThresholdPolicy{Severity: finding.SeverityHigh},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithAudit(context.Background(), []string{"audit", ".", "--fail-on", "high"}, &stdout, &stderr, fakeAudit)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if strings.Contains(stderr.String(), "Error:") {
		t.Errorf("expected NO synthetic Error line in stderr, got %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "scan finished with exit code 1") {
		t.Errorf("expected NO 'scan finished with exit code 1' line, got %q", stderr.String())
	}
	if stdout.String() == "" {
		t.Errorf("expected report to be printed to stdout")
	}
}
