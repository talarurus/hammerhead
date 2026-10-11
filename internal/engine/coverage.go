package engine

import (
	"time"

	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/git"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Known zero work and incomplete inventory describe an unstarted scan; they
// never assert absence of target files. Initialization performs no target I/O.
func initialCoverage(config *fs.WalkerConfig, limits scanstate.Limits) scanstate.Coverage {
	exclusions, policy := config.Policy()
	for key, value := range map[string]int64{
		"max_git_detection_ancestor_steps": int64(git.MaxDetectionAncestorSteps),
		"max_aggregate_native_read_bytes":  limits.MaxAggregateReadBytes,
		"max_findings_retained":            int64(limits.MaxFindings),
		"max_diagnostic_samples":           int64(limits.MaxDiagnosticSamples),
		"max_examples_per_reason":          int64(limits.MaxExamplesPerReason),
		"max_diagnostic_path_bytes":        int64(limits.MaxDiagnosticPath),
		"max_safe_message_bytes":           int64(limits.MaxSafeMessage),
		"max_finding_path_bytes":           int64(limits.MaxFindingPath),
		"max_evidence_bytes":               int64(limits.MaxFindingEvidence),
		"max_title_bytes":                  int64(limits.MaxFindingTitle),
		"max_description_bytes":            int64(limits.MaxFindingDesc),
		"max_remediation_bytes":            int64(limits.MaxFindingRemediation),
		"sec001_max_eligible_bytes":        5 * 1024 * 1024,
		"git_command_timeout_ms":           int64(git.CommandTimeout / time.Millisecond),
		"max_git_stdout_bytes":             git.MaxStdoutBytes,
		"max_git_stderr_bytes":             git.MaxStderrBytes,
		"git_termination_grace_ms":         1000,
		"git_wait_cleanup_ms":              1000,
	} {
		policy[key] = value
	}
	return scanstate.Coverage{
		Policy:    scanstate.PolicyCoverage{Exclusions: exclusions, EffectiveLimits: policy},
		Traversal: scanstate.TraversalCoverage{ExaminedEntries: new(int), DiscoveredFiles: new(int), DiscoveredDirectories: new(int), InventoryComplete: new(bool), RootListingComplete: new(bool)},
		Reasons:   []scanstate.Reason{}, Checks: []scanstate.CheckCoverage{}, DiagnosticExamplesOmitted: new(int),
	}
}

func unstartedChecks(registry *Registry) []scanstate.CheckCoverage {
	checks := make([]scanstate.CheckCoverage, 0, registry.Count())
	for _, c := range registry.All() {
		version := c.Meta().Version
		checks = append(checks, scanstate.CheckCoverage{RuleID: c.Meta().ID, CheckVer: &version, Status: scanstate.CheckStatusNotRun, EligibleFiles: new(int), InspectedFiles: new(int), ReadBytes: new(int), ReasonCounts: []scanstate.Reason{}})
	}
	scanstate.SortCoverage(&scanstate.Coverage{Checks: checks})
	return checks
}
