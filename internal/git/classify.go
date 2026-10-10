package git

import (
	"errors"
	"strings"
)

var (
	ErrGitPermission    = errors.New("git permission or ownership failure")
	ErrGitConfiguration = errors.New("git configuration failure")
	ErrGitCorrupt       = errors.New("git metadata corruption")
	ErrDetachedHEAD     = errors.New("detached HEAD")
	ErrUnbornBranch     = errors.New("unborn branch")
)

// Only detection's exact ordinary C-locale diagnostic is non-applicable.
// Other recognized diagnostics retain safe failure categories. Unknown exit
// errors remain operational failures, including malformed/unrecognized stderr.
func classifyExit(args []string, code int, stderr string) error {
	// Quiet branch-state queries use exit 1 with no diagnostics for these
	// expected states. Exit 1 accompanied by any unknown diagnostic is a
	// failure, never a guessed detached/unborn branch.
	if code == 1 && stderr == "" {
		if len(args) == 3 && args[0] == "symbolic-ref" && args[1] == "--quiet" && args[2] == "HEAD" {
			return ErrDetachedHEAD
		}
		if len(args) == 4 && args[0] == "show-ref" && args[1] == "--verify" && args[2] == "--quiet" &&
			strings.HasPrefix(args[3], "refs/heads/") && len(args[3]) > len("refs/heads/") {
			return ErrUnbornBranch
		}
	}
	// Preserve the original stderr for quiet exits above. For known C-locale
	// diagnostics, remove only one terminating LF or CRLF, never other
	// whitespace or additional blank lines.
	if strings.HasSuffix(stderr, "\r\n") {
		stderr = strings.TrimSuffix(stderr, "\r\n")
	} else {
		stderr = strings.TrimSuffix(stderr, "\n")
	}
	if code == 128 && len(args) == 2 && args[0] == "rev-parse" && args[1] == "--show-toplevel" &&
		stderr == "fatal: not a git repository (or any of the parent directories): .git" {
		return ErrNotARepository
	}
	if strings.HasPrefix(stderr, "fatal: detected dubious ownership in repository at ") ||
		(strings.HasPrefix(stderr, "fatal: ") && strings.HasSuffix(stderr, ": Permission denied")) {
		return ErrGitPermission
	}
	if strings.HasPrefix(stderr, "fatal: bad config line ") || strings.HasPrefix(stderr, "error: invalid key: ") {
		return ErrGitConfiguration
	}
	if strings.HasPrefix(stderr, "fatal: bad object ") || strings.HasPrefix(stderr, "fatal: bad ref ") ||
		strings.HasPrefix(stderr, "fatal: loose object ") || stderr == "fatal: index file corrupt" ||
		stderr == "fatal: .git/index: index file smaller than expected" {
		return ErrGitCorrupt
	}
	return nil
}
