package engine

import (
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

// ScanResult holds the complete output of a scan operation.
type ScanResult struct {
	// Status is the core execution outcome.
	Status scanstate.Status

	// RepoRoot is the resolved repository root path.
	RepoRoot string

	// Findings is the list of all findings, sorted by severity (highest first).
	Findings []finding.Finding

	// ChecksRun is the number of checks that were executed.
	ChecksRun int

	// FailOn is the configured minimum severity that triggers a finding-based failure.
	FailOn finding.Severity

	// Diagnostics contains partial/failure conditions.
	Diagnostics []scanstate.Diagnostic

	// Coverage contains detailed run completion facts.
	Coverage scanstate.Coverage

	// Skipped contains files/directories skipped during traversal (legacy).
	Skipped []fs.SkippedEntry
}

// ThresholdExceeded returns true if the highest security finding severity meets or exceeds failOn.
// The failOn parameter is the minimum severity that triggers a finding-based failure.
func (r *ScanResult) ThresholdExceeded(failOn finding.Severity) bool {
	for _, f := range r.Findings {
		if f.AffectsSecurityRisk() && f.Severity >= failOn {
			return true
		}
	}
	return false
}

// ExitCode returns the operational exit code based on status and finding threshold.
//   - 0: completed successfully, and threshold not exceeded
//   - 1: completed successfully, but threshold exceeded
//   - 2: partial, failed, cancelled, or invalid configuration
func (r *ScanResult) ExitCode(failOn finding.Severity) int {
	if r.Status != scanstate.StatusCompleted {
		return 2
	}
	if r.ThresholdExceeded(failOn) {
		return 1
	}
	return 0
}
