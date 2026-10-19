package engine

import (
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Known zero work and incomplete inventory describe an unstarted scan; they
// never assert absence of target files. Initialization performs no target I/O.
func initialCoverage(config *fs.WalkerConfig, limits scanstate.Limits) scanstate.Coverage {
	exclusions, policy := config.Policy()
	for key, value := range map[string]int64{
		"max_aggregate_native_read_bytes": limits.MaxAggregateReadBytes,
		"max_findings_retained":           int64(limits.MaxFindings),
		"max_diagnostic_samples":          int64(limits.MaxDiagnosticSamples),
		"max_examples_per_reason":         int64(limits.MaxExamplesPerReason),
		"max_diagnostic_path_bytes":       int64(limits.MaxDiagnosticPath),
		"max_safe_message_bytes":          int64(limits.MaxSafeMessage),
		"max_finding_path_bytes":          int64(limits.MaxFindingPath),
		"max_evidence_bytes":              int64(limits.MaxFindingEvidence),
		"max_title_bytes":                 int64(limits.MaxFindingTitle),
		"max_description_bytes":           int64(limits.MaxFindingDesc),
		"max_remediation_bytes":           int64(limits.MaxFindingRemediation),
		"sec001_max_eligible_bytes":       5 * 1024 * 1024,
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
