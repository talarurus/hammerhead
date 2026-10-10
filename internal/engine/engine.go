package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/git"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

type ScanConfig struct {
	// ExcludePatterns are glob or path patterns to exclude from scanning.
	ExcludePatterns []string

	// LargeFileThreshold is the file size in bytes before flagging as a large file (FILE-002).
	LargeFileThreshold int64

	// SecurityReadLimit is the maximum file size in bytes that SafeWalker will read into memory.
	SecurityReadLimit int64

	// Walker configuration for filesystem traversal.
	Walker *fs.WalkerConfig

	// Limits holds per-run production boundaries. Internal testing use only.
	Limits *scanstate.Limits
}

// Engine runs security checks against a repository.
type Engine struct {
	registry *Registry
}

// New creates a scan engine with the given check registry.
func New(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// Scan runs all registered checks against the target directory.
func (e *Engine) Scan(ctx context.Context, targetDir string, config *ScanConfig) (*ScanResult, error) {
	var clonedConfig ScanConfig
	if config != nil {
		clonedConfig.LargeFileThreshold = config.LargeFileThreshold
		clonedConfig.SecurityReadLimit = config.SecurityReadLimit
		if config.ExcludePatterns != nil {
			clonedConfig.ExcludePatterns = make([]string, len(config.ExcludePatterns))
			copy(clonedConfig.ExcludePatterns, config.ExcludePatterns)
		}
		if config.Walker != nil {
			w := *config.Walker
			if w.ExcludePatterns != nil {
				w.ExcludePatterns = make([]string, len(config.Walker.ExcludePatterns))
				copy(w.ExcludePatterns, config.Walker.ExcludePatterns)
			}
			clonedConfig.Walker = &w
		}
		if config.Limits != nil {
			l := *config.Limits
			clonedConfig.Limits = &l
		}
	}
	config = &clonedConfig

	result := &ScanResult{
		Status:   scanstate.StatusCompleted,
		RepoRoot: targetDir,
	}

	// Precedence for status:
	// 1. cancellation
	// 2. setup failure -> failed
	// 3. incomplete required work -> partial
	// 4. completed

	// Helper to upgrade status following precedence rules
	upgradeStatus := func(newStatus scanstate.Status) {
		if result.Status == scanstate.StatusCancelled {
			return // cancelled is highest precedence
		}
		if newStatus == scanstate.StatusFailed {
			result.Status = scanstate.StatusFailed
			return
		}
		if newStatus == scanstate.StatusPartial && result.Status != scanstate.StatusFailed {
			result.Status = scanstate.StatusPartial
		}
		if newStatus == scanstate.StatusCancelled {
			result.Status = scanstate.StatusCancelled
		}
	}

	// Step 1: Detect Git repository.
	gitInfo, err := git.DetectRepo(ctx, targetDir)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, git.ErrGitCanceled) {
			upgradeStatus(scanstate.StatusCancelled)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "git_setup",
				Code:        scanstate.ReasonUserCancelled,
				SafeMessage: "Git repository detection cancelled",
			})
		} else if errors.Is(err, context.DeadlineExceeded) {
			upgradeStatus(scanstate.StatusCancelled)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "git_setup",
				Code:        scanstate.ReasonDeadlineExceeded,
				SafeMessage: "Scan cancelled due to timeout during Git detection",
			})
		} else if errors.Is(err, git.ErrGitTimeout) {
			upgradeStatus(scanstate.StatusPartial)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "git_setup",
				Code:        scanstate.ReasonGitTimeout,
				SafeMessage: "Git repository detection timed out",
			})
		} else {
			upgradeStatus(scanstate.StatusPartial)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "git_setup",
				Code:        scanstate.ReasonGitFailure,
				SafeMessage: "Git operations failed, reverting to native scan",
			})
		}
		// Continue scan natively without git info
		gitInfo = &git.RepoInfo{IsRepo: false}
	}

	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		upgradeStatus(scanstate.StatusFailed)
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage:       "setup",
			Code:        scanstate.ReasonInvalidRoot,
			SafeMessage: "Failed to resolve target directory",
		})
		return result, fmt.Errorf("resolving target directory: %w", err)
	}
	repoRoot := absTarget
	result.RepoRoot = repoRoot

	// Step 2: Walk the repository safely.
	walkerCfg := config.Walker
	if walkerCfg == nil {
		walkerCfg = &fs.WalkerConfig{}
	}
	if len(config.ExcludePatterns) > 0 {
		walkerCfg.ExcludePatterns = append(walkerCfg.ExcludePatterns, config.ExcludePatterns...)
	}
	if config.SecurityReadLimit > 0 {
		walkerCfg.MaxFileSize = config.SecurityReadLimit
	}
	var limits scanstate.Limits
	if config.Limits != nil {
		limits = *config.Limits
	} else {
		limits = scanstate.ProductionLimits()
	}

	walkerCfg.MaxAggregateReadBytes = limits.MaxAggregateReadBytes
	walkerCfg.MaxSkippedEntries = limits.MaxDiagnosticSamples
	walkerCfg.MaxExamplesPerReason = limits.MaxExamplesPerReason
	walkerCfg.MaxDiagnosticPath = limits.MaxDiagnosticPath
	walkerCfg.MaxSafeMessage = limits.MaxSafeMessage

	walker, err := fs.NewSafeWalker(repoRoot, walkerCfg)
	if err != nil {
		upgradeStatus(scanstate.StatusFailed)
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage:       "setup",
			Code:        scanstate.ReasonInvalidRoot,
			SafeMessage: "Failed to initialize walker",
		})
		return result, fmt.Errorf("initializing walker: %w", err)
	}

	walkedFiles, inv, walkErr := walker.Walk(ctx)
	var pendingTraversalDiag *scanstate.Diagnostic
	if walkErr != nil {
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			upgradeStatus(scanstate.StatusCancelled)
			code := scanstate.ReasonUserCancelled
			msg := "Scan cancelled by user"
			if errors.Is(walkErr, context.DeadlineExceeded) {
				code = scanstate.ReasonDeadlineExceeded
				msg = "Scan cancelled due to timeout"
			}
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "traversal",
				Code:        code,
				SafeMessage: msg,
			})
			return result, walkErr
		}
		if errors.Is(walkErr, fs.ErrRootSetupFailed) {
			// root setup failure -> FAILED
			upgradeStatus(scanstate.StatusFailed)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "traversal",
				Code:        scanstate.ReasonTraversalFailure,
				SafeMessage: "Root directory could not be opened or listed",
			})
			return result, walkErr
		}
		upgradeStatus(scanstate.StatusPartial)
		code := scanstate.ReasonTraversalFailure
		if errors.Is(walkErr, fs.ErrBudgetExhausted) {
			code = scanstate.ReasonBudgetExhaustion
		}
		pendingTraversalDiag = &scanstate.Diagnostic{
			Stage:       "traversal",
			Code:        code,
			SafeMessage: "Partial traversal completed due to error",
		}
	} else if !inv.InventoryComplete {
		upgradeStatus(scanstate.StatusPartial)
		pendingTraversalDiag = &scanstate.Diagnostic{
			Stage:       "traversal",
			Code:        scanstate.ReasonTraversalFailure,
			SafeMessage: "Partial traversal completed (directories skipped or limits exceeded)",
		}
	}

	// Step 3: Initialize collector
	// Combine sample budgets: reduce Collector's allowed samples by those already used
	collectorLimits := limits
	collectorLimits.MaxDiagnosticSamples -= (len(result.Diagnostics) + len(walker.Skipped()))
	if collectorLimits.MaxDiagnosticSamples < 0 {
		collectorLimits.MaxDiagnosticSamples = 0
	}

	collector := scanstate.NewCollector(collectorLimits)
	if pendingTraversalDiag != nil {
		collector.AddDiagnostic(*pendingTraversalDiag)
	}

	aggReadBytes := int64(0)
	readerConfig := fs.ReaderConfig{
		RootPath:           walker.Root(),
		AggregateReadBytes: &aggReadBytes,
		MaxAggregate:       int64(limits.MaxAggregateReadBytes),
		SecurityReadLimit:  config.SecurityReadLimit,
		IsExcluded:         walker.IsExcluded,
	}
	guardedReader, err := fs.NewGuardedReader(readerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize guarded reader: %w", err)
	}
	if guardedReader != nil {
		defer guardedReader.Close()
	}

	// Step 4: Build ScanContext for checks.
	sc := &check.ScanContext{
		RepoRoot: walker.Root(),
		Files:    toCheckFiles(walkedFiles),
		Git: &check.GitInfo{
			IsRepo: gitInfo.IsRepo,
			Root:   gitInfo.Root,
			Branch: gitInfo.Branch,
		},
		Inventory: &inv,
		ReadFile: func(relPath string, maxSize int64) fs.ReadOutcome {
			return guardedReader.ReadFile(ctx, relPath, fs.ReadOptions{MaxSize: maxSize})
		},
		Emit: collector.Emit,
		Options: check.CheckOptions{
			LargeFileThresholdBytes: config.LargeFileThreshold,
			MaxExamplesPerReason:    limits.MaxExamplesPerReason,
		},
	}

	// Step 5: Run all checks.
	checksRun := 0
	var finalErr error
	var emittedCancelDiag bool

	checkReportedReasons := make(map[scanstate.ReasonCode]*scanstate.Reason)

	for _, c := range e.registry.All() {
		chkCov := scanstate.CheckCoverage{
			RuleID:       c.Meta().ID,
			ReasonCounts: []scanstate.Reason{},
		}
		if v := c.Meta().Version; v != "" {
			vStr := v
			chkCov.CheckVer = &vStr
		}

		if ctx.Err() != nil {
			if !emittedCancelDiag {
				upgradeStatus(scanstate.StatusCancelled)
				code := scanstate.ReasonUserCancelled
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					code = scanstate.ReasonDeadlineExceeded
				}
				collector.AddDiagnostic(scanstate.Diagnostic{
					Stage:       "check",
					Code:        code,
					SafeMessage: "Scan cancelled before check execution",
				})
				emittedCancelDiag = true
				if finalErr == nil {
					finalErr = ctx.Err()
				}
			}
			chkCov.Status = scanstate.CheckStatusNotRun
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
			continue
		}

		if collector.Exhausted() {
			chkCov.Status = scanstate.CheckStatusNotRun
			chkCov.ReasonCounts = append(chkCov.ReasonCounts, scanstate.Reason{Code: scanstate.ReasonBudgetExhaustion, Count: 1})
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
			continue
		}

		checksRun++

		checkCovData := &check.Coverage{}
		sc.Coverage = checkCovData
		err := c.Run(ctx, sc)
		sc.Coverage = nil

		eligible := checkCovData.EligibleFiles
		inspected := checkCovData.InspectedFiles
		readBytes := checkCovData.ReadBytes

		chkCov.EligibleFiles = &eligible
		chkCov.InspectedFiles = &inspected
		chkCov.ReadBytes = &readBytes

		if len(checkCovData.Reasons) > 0 {
			chkCov.ReasonCounts = append(chkCov.ReasonCounts, checkCovData.Reasons...)
			for _, r := range checkCovData.Reasons {
				if existing, ok := checkReportedReasons[r.Code]; ok {
					existing.Count += r.Count
					for _, ex := range r.Examples {
						if len(existing.Examples) < limits.MaxExamplesPerReason {
							existing.Examples = append(existing.Examples, ex)
						}
					}
				} else {
					cp := r
					checkReportedReasons[r.Code] = &cp
				}
			}
		}

		if ctx.Err() != nil {
			code := scanstate.ReasonUserCancelled
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = scanstate.ReasonDeadlineExceeded
			}
			if !emittedCancelDiag {
				upgradeStatus(scanstate.StatusCancelled)
				collector.AddDiagnostic(scanstate.Diagnostic{
					Stage:       "check",
					Code:        code,
					SafeMessage: "Scan cancelled during check execution",
				})
				emittedCancelDiag = true
			}
			chkCov.Status = scanstate.CheckStatusCancelled
			chkCov.ReasonCounts = append(chkCov.ReasonCounts, scanstate.Reason{Code: code, Count: 1})
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)

			if err != nil && err != ctx.Err() && !errors.Is(err, scanstate.ErrBudgetExhausted) && !errors.Is(err, scanstate.ErrPayloadTooLarge) && !errors.Is(err, fs.ErrBudgetExhausted) {
				finalErr = err
			} else if finalErr == nil {
				finalErr = ctx.Err()
			}
			continue
		}

		if err != nil {
			if errors.Is(err, scanstate.ErrBudgetExhausted) || errors.Is(err, scanstate.ErrPayloadTooLarge) || errors.Is(err, fs.ErrBudgetExhausted) {
				upgradeStatus(scanstate.StatusPartial)
				chkCov.Status = scanstate.CheckStatusPartial
				chkCov.ReasonCounts = append(chkCov.ReasonCounts, scanstate.Reason{Code: scanstate.ReasonBudgetExhaustion, Count: 1})
			} else {
				upgradeStatus(scanstate.StatusPartial)
				collector.AddDiagnostic(scanstate.Diagnostic{
					Stage:       "check",
					Code:        scanstate.ReasonCheckFailure,
					RuleID:      c.Meta().ID,
					SafeMessage: "Check encountered an error during execution",
				})
				chkCov.Status = scanstate.CheckStatusFailed
				chkCov.ReasonCounts = append(chkCov.ReasonCounts, scanstate.Reason{Code: scanstate.ReasonCheckFailure, Count: 1})
			}
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
		} else {
			hasFailureReason := false
			for _, r := range checkCovData.Reasons {
				if r.Code != scanstate.ReasonUserCancelled && r.Code != scanstate.ReasonDeadlineExceeded {
					hasFailureReason = true
					break
				}
			}
			if walkErr != nil || collector.Exhausted() || hasFailureReason {
				upgradeStatus(scanstate.StatusPartial)
				chkCov.Status = scanstate.CheckStatusPartial
			} else {
				chkCov.Status = scanstate.CheckStatusCompleted
			}
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
		}
	}

	if collector.Exhausted() {
		upgradeStatus(scanstate.StatusPartial)
	}

	allFindings := collector.Findings()
	sort.Sort(finding.BySeverity(allFindings))

	result.Findings = allFindings
	result.ChecksRun = checksRun
	result.Skipped = walker.Skipped()

	sev, hasSec := collector.HighestObservedSecurity()
	result.highestObservedSecurity = sev
	result.hasObservedSecurity = hasSec

	result.attemptedCount = collector.Attempted()
	result.attemptedLowerBound = collector.AttemptedLowerBound()

	result.Coverage.FindingsRetained = len(allFindings)
	result.Coverage.FindingsTruncated = collector.Exhausted()

	discovered := inv.RetainedFiles
	invComplete := inv.InventoryComplete

	examined := inv.ExaminedEntries
	retainedDirs := inv.RetainedDirs
	rootListComp := inv.RootListComplete
	result.Coverage.Traversal.ExaminedEntries = &examined
	result.Coverage.Traversal.DiscoveredFiles = &discovered
	result.Coverage.Traversal.DiscoveredDirectories = &retainedDirs
	result.Coverage.Traversal.InventoryComplete = &invComplete
	result.Coverage.Traversal.RootListingComplete = &rootListComp

	result.Coverage.Policy.Exclusions = nil
	result.Coverage.Policy.EffectiveLimits = map[string]int64{
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
	}

	if result.Coverage.Checks == nil {
		result.Coverage.Checks = []scanstate.CheckCoverage{}
	}

	// Capture pre-collector diagnostics for exact aggregate counts
	reasonMap := make(map[scanstate.ReasonCode]int)
	for _, diag := range result.Diagnostics {
		reasonMap[diag.Code]++
	}

	result.Diagnostics = append(result.Diagnostics, collector.Diagnostics()...)

	// Add aggregate reasons from collector, which holds true counts for post-collector events
	for code, count := range collector.ReasonCounts() {
		result.Coverage.Reasons = append(result.Coverage.Reasons, scanstate.Reason{
			Code:              code,
			Count:             int(count),
			CountIsLowerBound: false,
			Examples:          []string{},
		})
	}

	// Merge reasons mapped from pre-collector diagnostics
	for code, count := range reasonMap {
		found := false
		for i, r := range result.Coverage.Reasons {
			if r.Code == code {
				result.Coverage.Reasons[i].Count += count
				found = true
				break
			}
		}
		if !found {
			result.Coverage.Reasons = append(result.Coverage.Reasons, scanstate.Reason{
				Code:              code,
				Count:             count,
				CountIsLowerBound: false,
				Examples:          []string{},
			})
		}
	}

	// Merge reasons collected specifically from checks (e.g. read failures)
	for code, r := range checkReportedReasons {
		found := false
		for i, cr := range result.Coverage.Reasons {
			if cr.Code == code {
				result.Coverage.Reasons[i].Count += r.Count
				for _, ex := range r.Examples {
					if len(result.Coverage.Reasons[i].Examples) < limits.MaxExamplesPerReason {
						result.Coverage.Reasons[i].Examples = append(result.Coverage.Reasons[i].Examples, ex)
					}
				}
				found = true
				break
			}
		}
		if !found {
			result.Coverage.Reasons = append(result.Coverage.Reasons, *r)
		}
	}

	sort.Slice(result.Coverage.Reasons, func(i, j int) bool {
		return result.Coverage.Reasons[i].Code < result.Coverage.Reasons[j].Code
	})

	omitted := collector.DiagnosticOmitted()
	if walker.SkippedOmitted() > 0 {
		if omitted < int(^uint(0)>>1)-walker.SkippedOmitted() {
			omitted += walker.SkippedOmitted()
		} else {
			omitted = int(^uint(0) >> 1)
		}
	}
	if omitted > 0 {
		result.Coverage.DiagnosticExamplesOmitted = &omitted
	}

	if walkErr != nil && finalErr == nil {
		finalErr = walkErr
	}

	return result, finalErr
}

// toCheckFiles converts walker output to the check package's FileInfo type.
func toCheckFiles(walked []fs.WalkedFile) []check.FileInfo {
	files := make([]check.FileInfo, len(walked))
	for i, w := range walked {
		files[i] = check.FileInfo{
			Path:    w.Path,
			AbsPath: w.AbsPath,
			Size:    w.Size,
			Mode:    w.Mode,
			IsDir:   w.IsDir,
		}
	}
	return files
}
