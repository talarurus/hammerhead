// Package git provides bounded Git metadata collection. Git may follow worktree
// metadata outside the audit root; this is separate from native content scope.
package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

var ErrMalformedGitOutput = errors.New("malformed git metadata output")

var ErrGitDetectionAmbiguous = errors.New("git repository detection is ambiguous")

// MaxDetectionAncestorSteps bounds existence probes after ambiguous detection.
const MaxDetectionAncestorSteps = 256

type commandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

// CollectSnapshot collects all Git context before checks run. The caller must
// first validate the native audit root. There is no raw metadata fallback.
func CollectSnapshot(ctx context.Context, path string) (scanstate.GitSnapshot, error) {
	s := unknownSnapshot()
	if err := ctx.Err(); err != nil {
		return failedSnapshot(s, err)
	}
	runner, err := NewGitRunner(path)
	if errors.Is(err, ErrGitNotFound) {
		s.Availability = scanstate.GitUnavailable
		s.Status = scanstate.CheckStatusUnavailable
		return s, nil
	}
	if err != nil {
		return failedSnapshot(s, err)
	}
	return collectSnapshot(ctx, path, runner)
}

func unknownSnapshot() scanstate.GitSnapshot {
	return scanstate.GitSnapshot{
		Availability:  scanstate.GitAvailabilityUnknown,
		Applicability: scanstate.GitApplicabilityUnknown,
		Status:        scanstate.CheckStatusPartial,
		BranchState:   scanstate.GitBranchUnknown,
	}
}

func failedSnapshot(s scanstate.GitSnapshot, err error) (scanstate.GitSnapshot, error) {
	s.Status = scanstate.CheckStatusPartial
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		s.Status = scanstate.CheckStatusCancelled
	}
	return s, err
}

func collectSnapshot(ctx context.Context, path string, runner commandRunner) (scanstate.GitSnapshot, error) {
	s := unknownSnapshot()
	s.Availability = scanstate.GitAvailable
	root, err := runner.Run(ctx, path, "rev-parse", "--show-toplevel")
	if errors.Is(err, ErrNotARepository) {
		// Git emits the same diagnostic for an ordinary directory and some
		// damaged HEAD states. Only accept non-applicability when a bounded
		// existence probe also establishes that no .git marker was encountered.
		// This never reads metadata content or synthesizes repository context.
		if probeErr := verifyNoGitMarker(ctx, path); probeErr != nil {
			return failedSnapshot(s, probeErr)
		}
		s.Applicability = scanstate.GitNonRepository
		s.Status = scanstate.CheckStatusNotApplicable
		return s, nil
	}
	if err != nil {
		return failedSnapshot(s, err)
	}
	// Remove exactly Git's terminating LF, preserving spaces/control bytes in paths.
	root, ok := commandLine(root)
	if !ok || !filepath.IsAbs(root) {
		return failedSnapshot(s, ErrMalformedGitOutput)
	}
	s.Root = filepath.Clean(root)
	// Normalize only the user-selected root alias; Git still owns metadata scope.
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return failedSnapshot(s, err)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return failedSnapshot(s, err)
	}
	s.Applicability = scanstate.GitRoot
	if filepath.Clean(target) != s.Root {
		s.Applicability = scanstate.GitSubdirectory
	}

	branch, err := runner.Run(ctx, path, "symbolic-ref", "--quiet", "HEAD")
	if errors.Is(err, ErrDetachedHEAD) {
		// Exit 1 is symbolic-ref's documented detached state. Verify the commit;
		// broken HEAD/object state must not be accepted as detached and clean.
		if _, err = runner.Run(ctx, path, "rev-parse", "--verify", "HEAD^{commit}"); err != nil {
			return failedSnapshot(s, err)
		}
		s.BranchState = scanstate.GitBranchDetached
	} else if err != nil {
		return failedSnapshot(s, err)
	} else {
		branch, ok = commandLine(branch)
		if !ok || strings.ContainsAny(branch, "\x00\r\n") {
			return failedSnapshot(s, ErrMalformedGitOutput)
		}
		branch, ok = strings.CutPrefix(branch, "refs/heads/")
		if !ok || branch == "" {
			return failedSnapshot(s, ErrMalformedGitOutput)
		}
		s.Branch = branch
		// A valid symbolic HEAD with an absent branch ref is explicitly unborn.
		// show-ref distinguishes absence (1) from invalid/corrupt refs (128).
		_, err = runner.Run(ctx, path, "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
		if errors.Is(err, ErrUnbornBranch) {
			s.BranchState = scanstate.GitBranchUnborn
		} else if err != nil {
			return failedSnapshot(s, err)
		} else {
			if _, err = runner.Run(ctx, path, "rev-parse", "--verify", "HEAD^{commit}"); err != nil {
				return failedSnapshot(s, err)
			}
			s.BranchState = scanstate.GitBranchNormal
		}
	}
	if s.Applicability == scanstate.GitSubdirectory {
		s.Status = scanstate.CheckStatusNotApplicable
		return s, nil
	}
	out, err := runner.Run(ctx, path, "status", "--porcelain=v1", "-z", "--ignore-submodules=all")
	if err != nil {
		return failedSnapshot(s, err)
	}
	modified, untracked, err := parsePorcelainZ(ctx, out)
	if err != nil {
		return failedSnapshot(s, err)
	}
	s.ModifiedCount, s.UntrackedCount = modified, untracked
	s.Status = scanstate.CheckStatusCompleted
	return s, nil
}

func verifyNoGitMarker(ctx context.Context, path string) error {
	dir, err := filepath.Abs(path)
	if err != nil {
		return ErrGitDetectionAmbiguous
	}
	for steps := 0; steps < MaxDetectionAncestorSteps; steps++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := os.Lstat(filepath.Join(dir, ".git"))
		if !errors.Is(err, os.ErrNotExist) {
			return ErrGitDetectionAmbiguous
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
	return ErrGitDetectionAmbiguous
}

func commandLine(out string) (string, bool) {
	if !strings.HasSuffix(out, "\n") {
		return "", false
	}
	line := strings.TrimSuffix(out, "\n")
	return line, line != "" && !strings.ContainsRune(line, '\x00')
}

// RepoInfo is a compatibility view for internal runner regression callers.
// Production orchestration uses CollectSnapshot's explicit state instead.
type RepoInfo struct {
	IsRepo       bool
	Root         string
	Branch       string
	Status       scanstate.CheckStatus
	Availability scanstate.GitAvailability
}

func DetectRepo(ctx context.Context, path string) (*RepoInfo, error) {
	s, err := CollectSnapshot(ctx, path)
	if err != nil {
		return nil, err
	}
	return &RepoInfo{
		IsRepo: s.Applicability == scanstate.GitRoot || s.Applicability == scanstate.GitSubdirectory,
		Root:   s.Root, Branch: s.Branch, Status: s.Status, Availability: s.Availability,
	}, nil
}

type WorktreeInfo struct {
	IsDirty        bool
	ModifiedCount  int
	UntrackedCount int
	DetachedHEAD   bool
	Status         scanstate.CheckStatus
	Availability   scanstate.GitAvailability
}

func GetWorktreeStatus(ctx context.Context, path string) (*WorktreeInfo, error) {
	s, err := CollectSnapshot(ctx, path)
	if err != nil {
		return nil, err
	}
	return &WorktreeInfo{
		IsDirty:       s.ModifiedCount > 0 || s.UntrackedCount > 0,
		ModifiedCount: s.ModifiedCount, UntrackedCount: s.UntrackedCount,
		DetachedHEAD: s.BranchState == scanstate.GitBranchDetached,
		Status:       s.Status, Availability: s.Availability,
	}, nil
}
