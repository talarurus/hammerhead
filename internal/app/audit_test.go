package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/app"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func TestApp_InvalidRoot(t *testing.T) {
	req := app.AuditRequest{
		TargetDir: "does-not-exist-1234",
	}

	res, err := app.Audit(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error for invalid root")
	}
	if !strings.Contains(err.Error(), "cannot access") {
		t.Errorf("expected error containing 'cannot access', got %q", err.Error())
	}
	if res != nil {
		t.Errorf("expected nil result on setup failure")
	}
}

func TestScanResult_ExitPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		status   scanstate.Status
		findings []finding.Finding
		policy   app.ThresholdPolicy
		wantCode int
	}{
		{
			name:     "completed, no findings",
			status:   scanstate.StatusCompleted,
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 0,
		},
		{
			name:   "completed, threshold hit (critical >= high)",
			status: scanstate.StatusCompleted,
			findings: []finding.Finding{
				{Class: finding.ClassSecurity, Severity: finding.SeverityCritical},
			},
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 1,
		},
		{
			name:   "completed, threshold not hit (medium < high)",
			status: scanstate.StatusCompleted,
			findings: []finding.Finding{
				{Class: finding.ClassSecurity, Severity: finding.SeverityMedium},
			},
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 0,
		},
		{
			name:   "completed, threshold hit but policy disabled",
			status: scanstate.StatusCompleted,
			findings: []finding.Finding{
				{Class: finding.ClassSecurity, Severity: finding.SeverityCritical},
			},
			policy:   app.ThresholdPolicy{Disabled: true},
			wantCode: 0,
		},
		{
			name:   "completed, hygiene finding never triggers exit 1 even if critical",
			status: scanstate.StatusCompleted,
			findings: []finding.Finding{
				{Class: finding.ClassHygiene, Severity: finding.SeverityCritical},
			},
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityLow},
			wantCode: 0,
		},
		{
			name:     "partial status yields exit 2",
			status:   scanstate.StatusPartial,
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 2,
		},
		{
			name:     "failed status yields exit 2",
			status:   scanstate.StatusFailed,
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 2,
		},
		{
			name:     "cancelled status yields exit 2",
			status:   scanstate.StatusCancelled,
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 2,
		},
		{
			name:     "invalid/unset status yields exit 2",
			status:   "", // 0 default
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 2,
		},
		{
			name:     "failed status with policy disabled still yields exit 2",
			status:   scanstate.StatusFailed,
			policy:   app.ThresholdPolicy{Disabled: true},
			wantCode: 2,
		},
		{
			name:     "nil result yields exit 2",
			status:   "",
			policy:   app.ThresholdPolicy{Disabled: false, Severity: finding.SeverityHigh},
			wantCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result *engine.ScanResult
			if tt.name != "nil result yields exit 2" {
				result = &engine.ScanResult{
					Status:   tt.status,
					Findings: tt.findings,
				}
				for _, f := range tt.findings {
					if f.Class == finding.ClassSecurity {
						result.RecordObservedSecurity(f.Severity)
					}
				}
			}

			got := app.ExitCode(result, tt.policy)
			if got != tt.wantCode {
				t.Errorf("ExitCode() = %v, want %v", got, tt.wantCode)
			}
		})
	}
}

func TestApp_TypedValidation(t *testing.T) {
	validDir := t.TempDir()

	tests := []struct {
		name    string
		req     app.AuditRequest
		wantErr string
	}{
		{
			name: "negative MaxFileSize",
			req: app.AuditRequest{
				TargetDir:   validDir,
				MaxFileSize: -1,
			},
			wantErr: "invalid negative max file size",
		},
		{
			name: "invalid FailOn enum",
			req: app.AuditRequest{
				TargetDir:  validDir,
				FailOn:     finding.Severity(999), // Invalid severity
				FailOnNone: false,
			},
			wantErr: "invalid severity enum value",
		},
		{
			name: "malformed ExcludePatterns",
			req: app.AuditRequest{
				TargetDir:       validDir,
				ExcludePatterns: []string{"["}, // Malformed pattern
			},
			wantErr: "invalid exclude pattern",
		},
		{
			name: "valid request",
			req: app.AuditRequest{
				TargetDir:       validDir,
				MaxFileSize:     1024,
				FailOn:          finding.SeverityHigh,
				FailOnNone:      false,
				ExcludePatterns: []string{"*.go"},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := app.Audit(context.Background(), tt.req)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				if res != nil {
					t.Errorf("expected nil response on validation error, got %v", res)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if res == nil {
					t.Fatalf("expected non-nil response for valid request")
				}
			}
		})
	}
}
