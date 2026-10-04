package check

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/git"
)

const (
	gitHealthCheckID      = "GIT-002"
	gitHealthCheckName    = "git-health-context"
	gitHealthCheckVersion = "0.1.0"
)

// GitHealthCheck reports repository context including worktree cleanliness
// and HEAD state.
//
// All findings produced by this check are categorized as CategoryGit with
// SeverityInfo. A dirty worktree is normal during development and is surfaced
// for context and audit completeness, never as a security vulnerability.
type GitHealthCheck struct{}

func (c *GitHealthCheck) Meta() Meta {
	return Meta{
		ID:          gitHealthCheckID,
		Name:        gitHealthCheckName,
		Category:    finding.CategoryGit,
		Description: "Inspects Git repository worktree cleanliness and HEAD status as informational context",
		Version:     gitHealthCheckVersion,
	}
}

func (c *GitHealthCheck) Run(_ context.Context, sc *ScanContext) ([]finding.Finding, error) {
	if sc.Git == nil || !sc.Git.IsRepo {
		return nil, nil
	}

	// Only inspect worktree status if the audited directory is the root of the Git repo.
	// When auditing a subfolder (e.g. testdata fixtures or submodules), skip whole-repo worktree status.
	if filepath.Clean(sc.RepoRoot) != filepath.Clean(sc.Git.Root) {
		return nil, nil
	}

	targetDir := sc.RepoRoot
	if sc.Git.Root != "" {
		targetDir = sc.Git.Root
	}

	status, err := git.GetWorktreeStatus(targetDir)
	if err != nil {
		// Non-fatal: if git status fails (e.g. corrupted repo), return error to scan result warnings
		return nil, fmt.Errorf("retrieving git status: %w", err)
	}

	var findings []finding.Finding

	if status.IsDirty {
		evidence := fmt.Sprintf("Modified files: %d, Untracked files: %d", status.ModifiedCount, status.UntrackedCount)
		findings = append(findings, finding.Finding{
			ID:          finding.GenerateID(gitHealthCheckID, "dirty-worktree"),
			RuleID:      gitHealthCheckID,
			Class:       finding.ClassInfo,
			Category:    finding.CategoryGit,
			Severity:    finding.SeverityInfo,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Uncommitted changes in repository worktree",
			Description: "The working directory contains uncommitted modifications or untracked files. This is ordinary during development; verify that no unintended local files or sensitive configurations are staged.",
			Remediation: "Review modified and untracked files with 'git status' and 'git diff' before committing or publishing releases.",
			Path:        ".",
			Evidence:    evidence,
			Source:      "hammerhead",
			CheckVer:    gitHealthCheckVersion,
		})
	}

	if status.DetachedHEAD {
		findings = append(findings, finding.Finding{
			ID:          finding.GenerateID(gitHealthCheckID, "detached-head"),
			RuleID:      gitHealthCheckID,
			Class:       finding.ClassInfo,
			Category:    finding.CategoryGit,
			Severity:    finding.SeverityInfo,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Repository in detached HEAD state",
			Description: "The repository HEAD is currently detached from any local branch. Commits made in this state may become unreachable if not tagged or branched.",
			Remediation: "If this state is unintentional, switch to a named branch using 'git checkout <branch>' or 'git switch <branch>'.",
			Path:        ".",
			Evidence:    "HEAD is detached",
			Source:      "hammerhead",
			CheckVer:    gitHealthCheckVersion,
		})
	}

	return findings, nil
}
