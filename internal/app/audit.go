package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

type AuditRequest struct {
	TargetDir       string
	FailOn          finding.Severity
	FailOnNone      bool
	ExcludePatterns []string
	MaxFileSize     int64
}

type AuditResponse struct {
	Result    *engine.ScanResult
	Threshold ThresholdPolicy
}

type ThresholdPolicy struct {
	Disabled bool
	Severity finding.Severity
}

// Audit validates inputs and runs the scan exactly once without mutating checks.
func Audit(ctx context.Context, req AuditRequest) (*AuditResponse, error) {
	// 1. Typed request validation
	target := req.TargetDir
	if target == "" {
		target = "."
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %q: %w", target, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", target)
	}

	if req.MaxFileSize < 0 {
		return nil, fmt.Errorf("invalid negative max file size: %d", req.MaxFileSize)
	}

	if !req.FailOnNone {
		// Validating enum severity bounds
		if req.FailOn < finding.SeverityInfo || req.FailOn > finding.SeverityCritical {
			return nil, fmt.Errorf("invalid severity enum value: %v", req.FailOn)
		}
	}

	for _, pat := range req.ExcludePatterns {
		if _, err := filepath.Match(pat, "test"); err != nil {
			return nil, fmt.Errorf("invalid exclude pattern %q: %w", pat, err)
		}
	}

	policy := ThresholdPolicy{
		Disabled: req.FailOnNone,
		Severity: req.FailOn,
	}

	// Copy caller-provided slices
	excludes := make([]string, len(req.ExcludePatterns))
	copy(excludes, req.ExcludePatterns)

	// Build the engine with the explicit default registry.
	registry := engine.DefaultRegistry()
	eng := engine.New(registry)

	config := &engine.ScanConfig{
		ExcludePatterns:    excludes,
		LargeFileThreshold: req.MaxFileSize,
	}

	// Run the scan.
	result, runErr := eng.Scan(ctx, target, config)
	if result == nil {
		return nil, fmt.Errorf("scan failed: %w", runErr)
	}

	return &AuditResponse{
		Result:    result,
		Threshold: policy,
	}, runErr
}

// ExitCode is the single authoritative exit resolver for the application.
//   - completed + no Security threshold hit -> 0
//   - completed + Security threshold hit -> 1
//   - partial -> 2
//   - failed -> 2
//   - cancelled -> 2
//   - invalid/unset status -> 2
//   - Disabled/none + completed -> 0
//   - Disabled/none + partial/failed/cancelled -> 2
//   - Hygiene/Info never produce exit 1
func ExitCode(result *engine.ScanResult, policy ThresholdPolicy) int {
	if result == nil || result.Status != scanstate.StatusCompleted {
		return 2
	}
	if !policy.Disabled && result.ThresholdExceeded(policy.Severity) {
		return 1
	}
	return 0
}
