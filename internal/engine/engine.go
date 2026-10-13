package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/git"
	"github.com/talarurus/hammerhead/internal/scanstate"
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
	registry  *Registry
	newReader func(fs.ReaderConfig) (fs.GuardedReader, error)
}

// New creates a scan engine with the given check registry.
func New(registry *Registry) *Engine {
	return &Engine{registry: registry, newReader: fs.NewGuardedReader}
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

	result := &ScanResult{
		Status:   scanstate.StatusCompleted,
		RepoRoot: targetDir,
		Coverage: initialCoverage(walkerCfg, limits),
	}

	defer func() {
		if len(result.Coverage.Checks) == 0 {
			result.Coverage.Checks = unstartedChecks(e.registry)
		}
	}()

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

	// Reject pre-cancelled requests before any root or Git access.
	if err := ctx.Err(); err != nil {
		result.Status = scanstate.StatusCancelled
		code := scanstate.ReasonUserCancelled
		if errors.Is(err, context.DeadlineExceeded) {
			code = scanstate.ReasonDeadlineExceeded
		}
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage: "setup", Code: code, SafeMessage: "Scan cancelled before root validation",
		})
		return result, err
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

	// The engine owns the authority from establishment through all native work.
	// Traversal and reader construction borrow it and own their derived handles.
	root, err := walker.OpenRoot()
	if err != nil {
		upgradeStatus(scanstate.StatusFailed)
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage: "setup", Code: scanstate.ReasonInvalidRoot, SafeMessage: "Failed to open trusted root",
		})
		return result, fmt.Errorf("opening trusted root: %w", err)
	}
	defer root.Close()
	walkedFiles, inv, walkErr := walker.WalkRoot(ctx, root)
	result.Coverage.Traversal = scanstate.TraversalCoverage{
		ExaminedEntries:       &inv.ExaminedEntries,
		DiscoveredFiles:       &inv.RetainedFiles,
		DiscoveredDirectories: &inv.RetainedDirs,
		InventoryComplete:     &inv.InventoryComplete,
		RootListingComplete:   &inv.RootListComplete,
	}

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

	// Collect Git once, after native root establishment, through an admitted
	// private metadata capability. Native checks remain independent.
	var pendingGitDiag *scanstate.Diagnostic
	gitInfo, gitErr := collectRootGit(ctx, walker.Root(), root)
	if gitErr != nil {
		code := scanstate.ReasonGitFailure
		message := "Git metadata collection failed; native checks remain available"
		if errors.Is(gitErr, git.ErrUnsafeGitMetadata) {
			message = "Git evaluation refused because metadata safety could not be established; native checks remain available"
		}
		if ctx.Err() != nil {
			upgradeStatus(scanstate.StatusCancelled)
			code = scanstate.ReasonUserCancelled
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = scanstate.ReasonDeadlineExceeded
			}
			message = "Scan cancelled during Git metadata collection"
		} else {
			upgradeStatus(scanstate.StatusPartial)
			if errors.Is(gitErr, git.ErrGitTimeout) {
				code = scanstate.ReasonGitTimeout
			}
		}
		pendingGitDiag = &scanstate.Diagnostic{
			Stage: "git", RuleID: "GIT-002", Code: code, SafeMessage: message,
		}
	} else if gitInfo.Availability == scanstate.GitUnavailable {
		pendingGitDiag = &scanstate.Diagnostic{
			Stage: "git", RuleID: "GIT-002", Code: scanstate.ReasonGitUnavailable,
			SafeMessage: "Git executable unavailable; Git health was not evaluated",
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
	if pendingGitDiag != nil {
		collector.AddDiagnostic(*pendingGitDiag)
	}

	aggReadBytes := int64(0)
	readerConfig := fs.ReaderConfig{
		Root:               root,
		AggregateReadBytes: &aggReadBytes,
		MaxAggregate:       int64(limits.MaxAggregateReadBytes),
		SecurityReadLimit:  config.SecurityReadLimit,
		IsExcluded:         walker.IsExcluded,
	}
	guardedReader, err := e.newReader(readerConfig)
	if err != nil {
		// Retain inventory-only observations even if reader setup fails. Read
		// consumers receive an ordinary error through existing coverage handling.
		upgradeStatus(scanstate.StatusPartial)
		collector.AddDiagnostic(scanstate.Diagnostic{Stage: "setup", Code: scanstate.ReasonEligibleReadFailure, SafeMessage: "Failed to initialize rooted content reader"})
	}
	if guardedReader != nil {
		defer guardedReader.Close()
	}

	// Step 4: Build ScanContext for checks.
	sc := &check.ScanContext{
		RepoRoot:  walker.Root(),
		Files:     toCheckFiles(walkedFiles),
		Git:       &gitInfo,
		Inventory: &inv,
		ReadFile: func(relPath string, maxSize int64) fs.ReadOutcome {
			if guardedReader == nil {
				return fs.ReadOutcome{Status: fs.ReadStatusError, Err: err}
			}
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
	if ctx.Err() != nil {
		finalErr = ctx.Err()
	}
	var emittedCancelDiag bool

	checkReportedReasons := make(map[scanstate.ReasonCode]*scanstate.Reason)

	for _, c := range e.registry.All() {
		// An unstarted check inspected/read exactly zero entries. This is known
		// accounting, not fabricated completeness of undiscovered target data.
		eligible, inspected, readBytes := 0, 0, 0
		chkCov := scanstate.CheckCoverage{
			RuleID:         c.Meta().ID,
			ReasonCounts:   []scanstate.Reason{},
			EligibleFiles:  &eligible,
			InspectedFiles: &inspected,
			ReadBytes:      &readBytes,
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

		eligible = checkCovData.EligibleFiles
		inspected = checkCovData.InspectedFiles
		readBytes = checkCovData.ReadBytes

		chkCov.EligibleFiles = &eligible
		chkCov.InspectedFiles = &inspected
		chkCov.ReadBytes = &readBytes

		if len(checkCovData.Reasons) > 0 {
			chkCov.ReasonCounts = append(chkCov.ReasonCounts, checkCovData.Reasons...)
			for _, r := range checkCovData.Reasons {
				if existing, ok := checkReportedReasons[r.Code]; ok {
					existing.Count += r.Count
					for _, ex := range r.Examples {
						existing.Examples = scanstate.RetainExample(existing.Examples, ex, limits.MaxExamplesPerReason)
					}
				} else {
					cp := r
					cp.Examples = slices.Clone(r.Examples)
					slices.Sort(cp.Examples)
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
			if c.Meta().ID == "GIT-002" && !collector.Exhausted() {
				// Git health coverage follows the snapshot; filesystem traversal
				// cannot fabricate availability or applicability of Git work.
				chkCov.Status = gitInfo.Status
			} else if walkErr != nil || collector.Exhausted() || hasFailureReason {
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
					result.Coverage.Reasons[i].Examples = scanstate.RetainExample(result.Coverage.Reasons[i].Examples, ex, limits.MaxExamplesPerReason)
				}
				found = true
				break
			}
		}
		if !found {
			result.Coverage.Reasons = append(result.Coverage.Reasons, *r)
		}
	}

	scanstate.SortCoverage(&result.Coverage)
	slices.SortFunc(result.Diagnostics, scanstate.CompareDiagnostic)

	omitted := collector.DiagnosticOmitted()
	if walker.SkippedOmitted() > 0 {
		if omitted < int(^uint(0)>>1)-walker.SkippedOmitted() {
			omitted += walker.SkippedOmitted()
		} else {
			omitted = int(^uint(0) >> 1)
		}
	}
	result.Coverage.DiagnosticExamplesOmitted = &omitted

	if walkErr != nil && finalErr == nil {
		finalErr = walkErr
	}

	return result, finalErr
}

// Git's pathname authority is observed for the entire collection interval.
// Any lost/changed binding or observation failure discards all Git facts, even
// a non-repository result. Native descriptors continue to refer to the original
// object. This does not freeze file contents, Git metadata or external worktrees.
func collectRootGit(ctx context.Context, path string, root *fs.RootHandle) (snapshot scanstate.GitSnapshot, resultErr error) {
	unknown := scanstate.GitSnapshot{Availability: scanstate.GitAvailabilityUnknown, Applicability: scanstate.GitApplicabilityUnknown, Status: scanstate.CheckStatusPartial, BranchState: scanstate.GitBranchUnknown}
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	// Refuse excessive discovery depth before R1 allocates ancestor watches.
	// This path can yield only refusal/unavailable, never repository facts.
	if strings.Count(filepath.Clean(path), string(filepath.Separator))+1 > git.MaxDetectionAncestorSteps {
		return git.CollectSnapshot(ctx, path)
	}
	guard, err := root.GuardPath()
	if err != nil {
		return unknown, fmt.Errorf("Git root binding could not be established")
	}
	defer func() {
		if err := guard.Close(); err != nil {
			snapshot = unknown
			resultErr = errors.Join(resultErr, fmt.Errorf("closing Git root observer: %w", err))
		}
	}()
	if err := guard.Check(); err != nil {
		return unknown, fmt.Errorf("Git root binding changed")
	}
	snapshot, gitErr := git.CollectSnapshot(ctx, path)
	if err := guard.Check(); err != nil {
		return unknown, errors.Join(gitErr, fmt.Errorf("Git root binding changed during collection"))
	}
	return snapshot, gitErr
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
