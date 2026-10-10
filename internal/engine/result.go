package engine

import (
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
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

	// Diagnostics contains partial/failure conditions.
	Diagnostics []scanstate.Diagnostic

	// Coverage contains detailed run completion facts.
	Coverage scanstate.Coverage

	// Skipped contains files/directories skipped during traversal (legacy).
	Skipped []fs.SkippedEntry

	// highestObservedSecurity tracks the highest severity of any security finding, including rejected ones.
	highestObservedSecurity finding.Severity
	hasObservedSecurity     bool

	attemptedCount      int
	attemptedLowerBound bool
}

// Attempted returns the total number of findings attempted to be emitted.
func (r *ScanResult) Attempted() int {
	return r.attemptedCount
}

// AttemptedLowerBound returns whether the Attempted count is a lower bound.
func (r *ScanResult) AttemptedLowerBound() bool {
	return r.attemptedLowerBound
}

func (r *ScanResult) HighestObservedSecuritySeverity() (finding.Severity, bool) {
	maxSev := r.highestObservedSecurity
	hasSec := r.hasObservedSecurity

	for _, f := range r.Findings {
		if f.Class == finding.ClassSecurity {
			if !hasSec {
				hasSec = true
				maxSev = f.Severity
			} else if f.Severity > maxSev {
				maxSev = f.Severity
			}
		}
	}

	return maxSev, hasSec
}

// RecordObservedSecurity updates the highest observed security severity.
// This is used by the engine to propagate the collector's observed state,
// and can also be used by tests to set up explicit states.
func (r *ScanResult) RecordObservedSecurity(sev finding.Severity) {
	if !r.hasObservedSecurity {
		r.hasObservedSecurity = true
		r.highestObservedSecurity = sev
	} else if sev > r.highestObservedSecurity {
		r.highestObservedSecurity = sev
	}
}

// ThresholdExceeded returns true if the highest security finding severity meets or exceeds failOn.
// The failOn parameter is the minimum severity that triggers a finding-based failure.
func (r *ScanResult) ThresholdExceeded(failOn finding.Severity) bool {
	maxSev, hasSec := r.HighestObservedSecuritySeverity()
	if hasSec && maxSev >= failOn {
		return true
	}
	return false
}
