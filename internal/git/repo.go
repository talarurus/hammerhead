// Package git provides Git repository detection and metadata extraction.
package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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
func DetectRepo(path string) (*RepoInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	// Check if git is available.
	if _, err := exec.LookPath("git"); err != nil {
		// git not installed — fall back to .git directory detection.
		return DetectRepoFallback(absPath)
	}

	// Use git rev-parse to find the repository root.
	root, err := gitCommand(absPath, "rev-parse", "--show-toplevel")
	if err != nil {
		// Not a git repository.
		return &RepoInfo{IsRepo: false}, nil
	}

	cleanRoot := filepath.Clean(strings.TrimSpace(root))

	// Get current branch.
	branch, _ := gitCommand(absPath, "rev-parse", "--abbrev-ref", "HEAD")

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
// It never executes hooks or arbitrary repository code.
func GetWorktreeStatus(dir string) (*WorktreeInfo, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return &WorktreeInfo{}, nil
	}

	out, err := gitCommand(dir, "status", "--porcelain")
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
	branch, _ := gitCommand(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if strings.TrimSpace(branch) == "HEAD" {
		info.DetachedHEAD = true
	}

	return info, nil
}

// gitCommand runs a git command in the given directory and returns stdout.
// Arguments are passed as a discrete list — never through a shell.
func gitCommand(dir string, args ...string) (string, error) {
	// Harden Git execution against malicious repository configuration.
	safeArgs := []string{
		"--no-pager",
		"-c", "core.fsmonitor=",
		"-c", "core.hooksPath=/dev/null",
	}
	safeArgs = append(safeArgs, args...)

	cmd := exec.Command("git", safeArgs...)
	cmd.Dir = dir

	// Do not inherit the full parent environment.
	// Set only what git needs, and explicitly disable global/system configuration.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GIT_TERMINAL_PROMPT=0",       // Never prompt for credentials.
		"GIT_CONFIG_GLOBAL=/dev/null", // Ignore user's global gitconfig
		"GIT_CONFIG_SYSTEM=/dev/null", // Ignore system gitconfig
		"GIT_CONFIG_NOSYSTEM=1",       // Backup mechanism to ignore system config
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (stderr: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
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
