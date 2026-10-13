package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrGitNotFound       = errors.New("git executable not found")
	ErrGitTimeout        = errors.New("git command timed out")
	ErrGitCanceled       = errors.New("git command canceled")
	ErrStdoutLimit       = errors.New("git stdout limit exceeded")
	ErrStderrLimit       = errors.New("git stderr limit exceeded")
	ErrUnsafeGitPath     = errors.New("git executable path is unsafe")
	ErrNotARepository    = errors.New("not a git repository")
	ErrGitCleanupTimeout = errors.New("git cleanup timed out")
)

// GitExitError represents a non-zero exit code from a git command.
type GitExitError struct {
	ExitCode int
	Kind     error // Safe classification; raw stderr is never exposed.
}

func (e *GitExitError) Error() string {
	return fmt.Sprintf("git exited with code %d", e.ExitCode)
}

func (e *GitExitError) Unwrap() error { return e.Kind }

const (
	CommandTimeout = 10 * time.Second
	MaxStdoutBytes = 4 * 1024 * 1024 // 4 MiB
	MaxStderrBytes = 64 * 1024       // 64 KiB
)

type GitRunner struct {
	gitPath    string
	lookupPath string
}

func NewGitRunner(targetDir string) (*GitRunner, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		if errors.Is(err, exec.ErrDot) {
			return nil, ErrUnsafeGitPath
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, ErrGitNotFound
		}
		// Lookup errors can contain untrusted PATH entries. Do not expose them
		// or allow them to enter the missing-Git fallback.
		return nil, ErrUnsafeGitPath
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving git abs path: %w", err)
	}

	var targets []string
	if targetDir != "" {
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			return nil, fmt.Errorf("resolving target abs path: %w", err)
		}
		evalTarget, err := filepath.EvalSymlinks(absTarget)
		if err != nil {
			return nil, fmt.Errorf("evaluating target symlinks: %w", err)
		}
		targets = []string{absTarget, evalTarget}
	}

	lookupPath := path
	path, err = resolveTrustedGitPath(path, targets)
	if err != nil {
		return nil, err
	}

	return &GitRunner{gitPath: path, lookupPath: lookupPath}, nil
}

// Check every symlink hop, including aliases that leave the target again.
// Checking only the final destination would trust target-owned symlinks.
func resolveTrustedGitPath(path string, targets []string) (string, error) {
	for links := 0; links < 255; links++ {
		for _, target := range targets {
			rel, err := filepath.Rel(target, path)
			if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return "", ErrUnsafeGitPath
			}
		}

		parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
		prefix := string(filepath.Separator)
		foundLink := false
		for i, part := range parts {
			prefix = filepath.Join(prefix, part)
			info, err := os.Lstat(prefix)
			if err != nil {
				return "", ErrUnsafeGitPath
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			dest, err := os.Readlink(prefix)
			if err != nil {
				return "", ErrUnsafeGitPath
			}
			if !filepath.IsAbs(dest) {
				dest = filepath.Join(filepath.Dir(prefix), dest)
			}
			path = filepath.Join(append([]string{dest}, parts[i+1:]...)...)
			foundLink = true
			break
		}
		if !foundLink {
			return path, nil
		}
	}
	return "", ErrUnsafeGitPath
}

func (r *GitRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !queryAllowed(args) {
		return "", refuse("unsupported query")
	}
	v, err := prepareMetadata(ctx, dir, r, newMetadataBudget(ctx))
	if err != nil {
		return "", err
	}
	out, runErr := v.Run(ctx, dir, args...)
	verifyErr := v.verify()
	closeErr := v.Close()
	if err := errors.Join(runErr, verifyErr, closeErr); err != nil {
		return "", err
	}
	return out, nil
}

func (r *GitRunner) runControlled(ctx context.Context, v *metadataView, dir string, args ...string) (_ string, d2ResultErr error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v == nil || v.closed || v.dir == "" || v.home == "" {
		return "", refuse("missing view capability")
	}
	v.budget.commands++
	if v.budget.commands > 8 {
		return "", refuse("child budget")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	d2Trace := d2BeginChild(ctx, cmdCtx, args)
	defer func() {
		d2Trace.finish(d2ResultErr)
		cancel()
	}()

	safeArgs := []string{
		"--no-pager",
		"--no-lazy-fetch",
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.untrackedCache=false",
	}
	safeArgs = append(safeArgs, args...)

	cmd := exec.Command(r.gitPath, safeArgs...)
	cmd.Dir = dir
	setupSysProcAttr(cmd)

	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + v.home,
		"XDG_CONFIG_HOME=" + filepath.Join(v.home, "xdg"),
		"GIT_DIR=" + v.dir,
		"GIT_WORK_TREE=" + v.root,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_ATTR_NOSYSTEM=1",
		"LC_ALL=C",
	}
	if len(args) == 2 && args[0] == "var" && args[1] == "GIT_ATTR_SYSTEM" {
		// var reports the compiled runtime path without reading attributes.
		cmd.Env[len(cmd.Env)-2] = "GIT_ATTR_NOSYSTEM=0"
	}

	cmd.WaitDelay = 1 * time.Second

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	outW := &limitWriter{buf: stdoutBuf, limit: MaxStdoutBytes, cancel: cancel}
	errW := &limitWriter{buf: stderrBuf, limit: MaxStderrBytes, cancel: cancel}

	cmd.Stdout = outW
	cmd.Stderr = errW
	if d2Trace != nil {
		d2Trace.cmd, d2Trace.stderr = cmd, stderrBuf
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting git: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if d2Trace != nil {
			d2Trace.complete.Store(true)
		}
		waitDone <- err
	}()

	var waitErr error
	waited := false
	select {
	case <-cmdCtx.Done():
	case waitErr = <-waitDone:
		waited = true
	}

	waitErr, cleanupErr := cleanupProcessGroup(cmd, waitDone, waitErr, waited)
	if d2Trace != nil {
		d2Trace.waitErr, d2Trace.cleanupErr = waitErr, cleanupErr
	}
	v.budget.output += stdoutBuf.Len() + stderrBuf.Len()
	// The parent scan reason takes precedence over output overflow and the
	// command's private deadline. Retain any cleanup failure as well.
	if err := ctx.Err(); err != nil {
		return "", errors.Join(err, cleanupErr)
	}
	if cleanupErr != nil {
		return "", cleanupErr
	}
	if v.budget.output > metadataOutputBytes {
		return "", refuse("aggregate output budget")
	}

	if outW.overflowed {
		return "", ErrStdoutLimit
	}
	if errW.overflowed {
		return "", ErrStderrLimit
	}

	if cmdCtx.Err() != nil {
		return "", ErrGitTimeout
	}

	if errors.Is(waitErr, exec.ErrWaitDelay) {
		return "", ErrGitTimeout
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return stdoutBuf.String(), &GitExitError{
				ExitCode: exitErr.ExitCode(),
				Kind:     classifyExit(args, exitErr.ExitCode(), stderrBuf.String()),
			}
		}
		return stdoutBuf.String(), fmt.Errorf("git execution failed: %w", waitErr)
	}

	return stdoutBuf.String(), nil
}

// Wait for both the direct process (including its output readers) and the
// owned group. A reaped leader does not imply its descendants have exited.
// Once the group is absent, never signal that numeric group ID again.
func cleanupProcessGroup(cmd *exec.Cmd, waitDone <-chan error, waitErr error, waited bool) (error, error) {
	groupGone := !processGroupExists(cmd)
	if !groupGone {
		terminateProcessGroup(cmd)
	}
	grace := time.NewTimer(time.Second)
	defer grace.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	if waited {
		waitDone = nil
	}
	for {
		if !groupGone {
			groupGone = !processGroupExists(cmd)
		}
		if waited && groupGone {
			return waitErr, nil
		}
		select {
		case waitErr = <-waitDone:
			waited = true
			waitDone = nil
		case <-grace.C:
			if !groupGone && processGroupExists(cmd) {
				forceKillProcessGroup(cmd)
			} else {
				groupGone = true
			}
		case <-deadline.C:
			return waitErr, ErrGitCleanupTimeout
		case <-poll.C:
		}
	}
}

type limitWriter struct {
	buf        *bytes.Buffer
	limit      int
	cancel     context.CancelFunc
	overflowed bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.overflowed {
		return len(p), nil
	}
	if w.buf.Len()+len(p) > w.limit {
		w.buf.Write(p[:w.limit-w.buf.Len()])
		w.overflowed = true
		w.cancel()
		return len(p), nil
	}
	return w.buf.Write(p)
}
