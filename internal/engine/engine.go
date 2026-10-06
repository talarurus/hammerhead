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

// ScanConfig holds configuration for a scan operation.
type ScanConfig struct {
	// FailOn is the minimum severity that causes a non-zero exit code.
	// Findings below this threshold are reported but do not affect the exit code.
	FailOn finding.Severity

	// ExcludePatterns are glob or path patterns to exclude from scanning.
	ExcludePatterns []string

	// LargeFileThreshold is the file size in bytes before flagging as a large file (FILE-002).
	LargeFileThreshold int64

	// SecurityReadLimit is the maximum file size in bytes that SafeWalker will read into memory.
	SecurityReadLimit int64

	// Walker configuration for filesystem traversal.
	Walker *fs.WalkerConfig
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
	if config == nil {
		config = &ScanConfig{
			FailOn: finding.SeverityHigh,
		}
	}

	result := &ScanResult{
		Status:   scanstate.StatusCompleted,
		RepoRoot: targetDir,
		FailOn:   config.FailOn,
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
	gitInfo, err := git.DetectRepo(targetDir)
	if err != nil {
		upgradeStatus(scanstate.StatusFailed)
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage:       "setup",
			Code:        scanstate.ReasonInvalidRoot,
			SafeMessage: "Failed to detect repository",
		})
		return result, fmt.Errorf("detecting repository: %w", err)
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
	} else {
		cpy := *walkerCfg
		walkerCfg = &cpy
	}
	if len(config.ExcludePatterns) > 0 {
		walkerCfg.ExcludePatterns = append(walkerCfg.ExcludePatterns, config.ExcludePatterns...)
	}
	if config.SecurityReadLimit > 0 {
		walkerCfg.MaxFileSize = config.SecurityReadLimit
	}

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

	walkedFiles, walkErr := walker.Walk()
	if walkErr != nil {
		upgradeStatus(scanstate.StatusPartial)
		code := scanstate.ReasonTraversalFailure
		if errors.Is(walkErr, fs.ErrBudgetExhausted) {
			code = scanstate.ReasonBudgetExhaustion
		}
		result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
			Stage:       "traversal",
			Code:        code,
			SafeMessage: "Partial traversal completed due to error",
		})
		// Keep going with what we have, even if 0 files, because checks like git/project can still run on root.
	}

	// Step 3: Build ScanContext for checks.
	sc := &check.ScanContext{
		RepoRoot: walker.Root(),
		Files:    toCheckFiles(walkedFiles),
		Git: &check.GitInfo{
			IsRepo: gitInfo.IsRepo,
			Root:   gitInfo.Root,
			Branch: gitInfo.Branch,
		},
		ReadFile: walker.SafeReadFile,
	}

	// Step 4: Run all checks.
	var allFindings []finding.Finding
	checksRun := 0
	var finalErr error

	var emittedCancelDiag bool

	for _, c := range e.registry.All() {
		chkCov := scanstate.CheckCoverage{
			RuleID:       c.Meta().ID,
			ReasonCounts: []scanstate.Reason{},
		}
		if v := c.Meta().Version; v != "" {
			vStr := v
			chkCov.CheckVer = &vStr
		}

		// Wire dynamic thresholds if configured
		if lfc, ok := c.(*check.LargeFileCheck); ok && config.LargeFileThreshold > 0 {
			lfc.ThresholdBytes = config.LargeFileThreshold
		}

		// Check context cancellation before each check.
		if ctx.Err() != nil {
			if !emittedCancelDiag {
				upgradeStatus(scanstate.StatusCancelled)
				code := scanstate.ReasonUserCancelled
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					code = scanstate.ReasonDeadlineExceeded
				}
				result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
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

		checksRun++
		findings, err := c.Run(ctx, sc)

		// Always append findings, even if err != nil, as checks might return partial findings.
		allFindings = append(allFindings, findings...)

		// Immediately inspect ctx.Err()
		if ctx.Err() != nil {
			code := scanstate.ReasonUserCancelled
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = scanstate.ReasonDeadlineExceeded
			}
			if !emittedCancelDiag {
				upgradeStatus(scanstate.StatusCancelled)
				result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
					Stage:       "check",
					Code:        code,
					SafeMessage: "Scan cancelled during check execution",
				})
				emittedCancelDiag = true
			}
			chkCov.Status = scanstate.CheckStatusCancelled
			chkCov.ReasonCounts = []scanstate.Reason{{
				Code:              code,
				Count:             1,
				CountIsLowerBound: false,
				Examples:          []string{},
			}}
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)

			if err != nil {
				finalErr = err
			} else if finalErr == nil {
				finalErr = ctx.Err()
			}
			continue
		}

		if err != nil {
			upgradeStatus(scanstate.StatusPartial)
			result.Diagnostics = append(result.Diagnostics, scanstate.Diagnostic{
				Stage:       "check",
				Code:        scanstate.ReasonCheckFailure,
				RuleID:      c.Meta().ID,
				SafeMessage: "Check encountered an error during execution",
			})
			chkCov.Status = scanstate.CheckStatusFailed
			chkCov.ReasonCounts = []scanstate.Reason{{
				Code:              scanstate.ReasonCheckFailure,
				Count:             1,
				CountIsLowerBound: false,
				Examples:          []string{},
			}}
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
		} else {
			// Unstarted check is not_run. Wait, this is for completed check!
			// If walk error is budget exhausted, maybe check is partial?
			// The prompt says: "if the repository inventory is incomplete because traversal failed, do not claim an inventory-dependent check has complete coverage merely because its Run method returned nil; use partial where appropriate"
			if walkErr != nil {
				chkCov.Status = scanstate.CheckStatusPartial
			} else {
				chkCov.Status = scanstate.CheckStatusCompleted
			}
			chkCov.ReasonCounts = []scanstate.Reason{}
			result.Coverage.Checks = append(result.Coverage.Checks, chkCov)
		}
	}

	// Step 5: Sort findings by severity (highest first).
	sort.Sort(finding.BySeverity(allFindings))

	result.Findings = allFindings
	result.ChecksRun = checksRun
	result.Skipped = walker.Skipped()

	// Populate genuine coverage data
	result.Coverage.FindingsRetained = len(allFindings)
	result.Coverage.FindingsTruncated = false // P1-01 does not truncate

	discovered := len(walkedFiles)
	invComplete := walkErr == nil

	// Fill Traversal coverage pointers
	result.Coverage.Traversal.ExaminedEntries = nil // Not explicitly tracked in P1-01
	result.Coverage.Traversal.DiscoveredFiles = &discovered
	result.Coverage.Traversal.InventoryComplete = &invComplete

	// Fill Policy coverage explicitly empty (null)
	result.Coverage.Policy.Exclusions = nil
	result.Coverage.Policy.EffectiveLimits = nil

	if result.Coverage.Checks == nil {
		result.Coverage.Checks = []scanstate.CheckCoverage{}
	}

	// Populate reasons mapping from diagnostics
	reasonMap := make(map[scanstate.ReasonCode]int)
	for _, diag := range result.Diagnostics {
		reasonMap[diag.Code]++
	}
	for code, count := range reasonMap {
		result.Coverage.Reasons = append(result.Coverage.Reasons, scanstate.Reason{
			Code:              code,
			Count:             count,
			CountIsLowerBound: false,
			Examples:          []string{},
		})
	}
	sort.Slice(result.Coverage.Reasons, func(i, j int) bool {
		return result.Coverage.Reasons[i].Code < result.Coverage.Reasons[j].Code
	})

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
