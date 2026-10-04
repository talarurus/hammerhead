package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/git"
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

// ScanResult holds the complete output of a scan operation.
type ScanResult struct {
	// RepoRoot is the resolved repository root path.
	RepoRoot string

	// Findings is the list of all findings, sorted by severity (highest first).
	Findings []finding.Finding

	// ChecksRun is the number of checks that were executed.
	ChecksRun int

	// Errors contains non-fatal errors from individual checks.
	// A check error does not prevent other checks from running.
	Errors []CheckError

	// Skipped contains files/directories skipped during traversal.
	Skipped []fs.SkippedEntry
}

// CheckError records a non-fatal error from an individual check.
type CheckError struct {
	CheckID string
	Err     error
}

func (e CheckError) Error() string {
	return fmt.Sprintf("check %s: %v", e.CheckID, e.Err)
}

// ExitCode returns the appropriate exit code based on security findings and threshold.
//
//	0 = no security findings at or above the FailOn threshold
//	1 = security findings at or above the FailOn threshold exist
func (r *ScanResult) ExitCode(failOn finding.Severity) int {
	for _, f := range r.Findings {
		if f.AffectsSecurityRisk() && f.Severity >= failOn {
			return 1
		}
	}
	return 0
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

	// Step 1: Detect Git repository.
	gitInfo, err := git.DetectRepo(targetDir)
	if err != nil {
		return nil, fmt.Errorf("detecting repository: %w", err)
	}

	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("resolving target directory: %w", err)
	}
	repoRoot := absTarget

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
		return nil, fmt.Errorf("initializing walker: %w", err)
	}

	walkedFiles, err := walker.Walk()
	if err != nil {
		// Walk returns partial results on some errors (e.g., file count exceeded).
		// Log the error but continue with what we have.
		// If we got zero files, that's a real problem.
		if len(walkedFiles) == 0 {
			return nil, fmt.Errorf("walking repository: %w", err)
		}
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
	var checkErrors []CheckError
	checksRun := 0

	for _, c := range e.registry.All() {
		// Wire dynamic thresholds if configured
		if lfc, ok := c.(*check.LargeFileCheck); ok && config.LargeFileThreshold > 0 {
			lfc.ThresholdBytes = config.LargeFileThreshold
		}

		// Check context cancellation before each check.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("scan cancelled: %w", ctx.Err())
		}

		checksRun++
		findings, err := c.Run(ctx, sc)
		if err != nil {
			checkErrors = append(checkErrors, CheckError{
				CheckID: c.Meta().ID,
				Err:     err,
			})
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Step 5: Sort findings by severity (highest first).
	sort.Sort(finding.BySeverity(allFindings))

	return &ScanResult{
		RepoRoot:  walker.Root(),
		Findings:  allFindings,
		ChecksRun: checksRun,
		Errors:    checkErrors,
		Skipped:   walker.Skipped(),
	}, nil
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
