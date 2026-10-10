// Package git provides Git repository detection and metadata extraction.
package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RepoInfo holds basic information about a Git repository.
type RepoInfo struct {
	IsRepo bool   // Whether the path is inside a Git repository
	Root   string // Absolute path to the repository root
	Branch string // Current branch name (may be empty for detached HEAD)
}

// DetectRepo determines if the given path is inside a Git repository
// and extracts basic metadata. This uses the git CLI rather than
// parsing .git internals to handle worktrees and other edge cases.
//
// If git is not installed, returns a RepoInfo with IsRepo=false.
func DetectRepo(ctx context.Context, path string) (*RepoInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	runner, err := NewGitRunner(absPath)
	if err != nil {
		if errors.Is(err, ErrGitNotFound) {
			return DetectRepoFallback(absPath)
		}
		return nil, fmt.Errorf("initializing git runner: %w", err)
	}

	// Use git rev-parse to find the repository root.
	root, err := runner.Run(ctx, absPath, "rev-parse", "--show-toplevel")
	if err != nil {
		if errors.Is(err, ErrNotARepository) {
			// Not a git repository.
			return &RepoInfo{IsRepo: false}, nil
		}
		return nil, fmt.Errorf("detecting repo: %w", err)
	}

	cleanRoot := filepath.Clean(strings.TrimSpace(root))

	// Get current branch.
	branch, err := runner.Run(ctx, absPath, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		if errors.Is(err, ErrUnbornBranch) {
			branch = ""
		} else {
			return nil, fmt.Errorf("getting branch: %w", err)
		}
	}

	return &RepoInfo{
		IsRepo: true,
		Root:   cleanRoot,
		Branch: strings.TrimSpace(branch),
	}, nil
}

// WorktreeInfo holds the working directory cleanliness status.
type WorktreeInfo struct {
	IsDirty        bool
	ModifiedCount  int
	UntrackedCount int
	DetachedHEAD   bool
}

// GetWorktreeStatus inspects the Git worktree status using 'git status --porcelain'.
// Submodule status is explicitly ignored to prevent uncontrolled recursive status inspection.
// It never executes hooks or arbitrary repository code.
func GetWorktreeStatus(ctx context.Context, dir string) (*WorktreeInfo, error) {
	runner, err := NewGitRunner(dir)
	if err != nil {
		if errors.Is(err, ErrGitNotFound) {
			return &WorktreeInfo{}, nil
		}
		return nil, fmt.Errorf("initializing git runner: %w", err)
	}

	out, err := runner.Run(ctx, dir, "status", "--porcelain", "--ignore-submodules=all")
	if err != nil {
		return nil, err
	}

	info := &WorktreeInfo{}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		info.IsDirty = true
		if strings.HasPrefix(trimmed, "??") {
			info.UntrackedCount++
		} else {
			info.ModifiedCount++
		}
	}

	// Check detached HEAD
	branch, err := runner.Run(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		if !errors.Is(err, ErrUnbornBranch) {
			return nil, fmt.Errorf("getting detached HEAD status: %w", err)
		}
	} else if strings.TrimSpace(branch) == "HEAD" {
		info.DetachedHEAD = true
	}

	return info, nil
}

// DetectRepoFallback detects a Git repo by looking for a .git directory.
// Used when the git CLI is not available.
func DetectRepoFallback(absPath string) (*RepoInfo, error) {
	dir := absPath
	for {
		gitDir := filepath.Join(dir, ".git")
		info, err := os.Stat(gitDir)
		if err == nil && info.IsDir() {
			return &RepoInfo{
				IsRepo: true,
				Root:   dir,
				Branch: readHeadBranch(gitDir),
			}, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root.
			return &RepoInfo{IsRepo: false}, nil
		}
		dir = parent
	}
}

// readHeadBranch attempts to read the current branch from .git/HEAD.
func readHeadBranch(gitDir string) string {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	// Format: "ref: refs/heads/main"
	if after, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
		return after
	}
	return "" // Detached HEAD or unexpected format.
}
