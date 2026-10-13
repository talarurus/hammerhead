package git

// D2 ONLY: observation for one helper-free fixture family. This file is never
// intended for the production branch. No output contains paths, argv, config,
// raw errors, environment values, or raw child output.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type d2ContextKey struct{}

func d2TestContext(ctx context.Context, name string) context.Context {
	switch name {
	case "normal", "unborn", "detached", "subdirectory", "alias":
		return context.WithValue(ctx, d2ContextKey{}, name)
	}
	return ctx
}
func d2Active(ctx context.Context) bool {
	name, _ := ctx.Value(d2ContextKey{}).(string)
	switch name {
	case "normal", "unborn", "detached", "subdirectory", "alias":
		return os.Getenv("HAMMERHEAD_D2_TRACE_DIR") != ""
	}
	return false
}

type d2Event struct {
	Phase               string `json:"phase"`
	Test                string `json:"test"`
	Stage               string `json:"stage"`
	Category            string `json:"category"`
	Errno               int    `json:"errno,omitempty"`
	Refusal             string `json:"refusal,omitempty"`
	ElapsedNS           int64  `json:"elapsed_ns"`
	ParentContext       string `json:"parent_context"`
	ChildContext        string `json:"child_context,omitempty"`
	DeadlineRemainingNS *int64 `json:"deadline_remaining_ns,omitempty"`
	ExitCode            *int   `json:"exit_code,omitempty"`
	Signal              int    `json:"signal,omitempty"`
	WaitCategory        string `json:"wait_category,omitempty"`
	CleanupCategory     string `json:"cleanup_category,omitempty"`
	IOComplete          bool   `json:"io_complete,omitempty"`
	StderrBytes         int    `json:"stderr_bytes,omitempty"`
	StderrCategory      string `json:"stderr_category,omitempty"`
}

func d2Category(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, ErrGitTimeout):
		return "git-timeout"
	case errors.Is(err, ErrGitCleanupTimeout):
		return "cleanup-timeout"
	case errors.Is(err, ErrStdoutLimit):
		return "stdout-limit"
	case errors.Is(err, ErrStderrLimit):
		return "stderr-limit"
	case errors.Is(err, ErrNotARepository):
		return "not-repository"
	case errors.Is(err, ErrUnsafeGitMetadata):
		return "security-refusal"
	case errors.Is(err, exec.ErrWaitDelay):
		return "wait-delay"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return "os-errno"
	}
	var exit *GitExitError
	if errors.As(err, &exit) {
		return "git-exit"
	}
	var child *exec.ExitError
	if errors.As(err, &child) {
		return "child-exit"
	}
	return "other-error"
}
func d2BuildEvent(ctx context.Context, stage string, start time.Time, err error) d2Event {
	name, _ := ctx.Value(d2ContextKey{}).(string)
	phase := os.Getenv("HAMMERHEAD_D2_PHASE")
	switch phase {
	case "full-normal", "full-race", "focused-race", "git-package-race", "local-validation":
	default:
		phase = "unknown"
	}
	e := d2Event{Phase: phase, Test: name, Stage: stage, Category: d2Category(err), ElapsedNS: time.Since(start).Nanoseconds(), ParentContext: d2Category(ctx.Err())}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		e.Errno = int(errno)
	}
	var refusal *MetadataRefusalError
	if errors.As(err, &refusal) {
		switch refusal.reason {
		case "system attributes lookup", "ambient home uncertainty", "ambient XDG uncertainty", "ambient symlink budget", "ambient path uncertainty", "ambient absence", "ambient symlink uncertainty", "ambient policy present or uncertain", "metadata directory", "directory type or ownership", "directory changed during open", "descriptor budget", "preparation command", "preparation command deadline", "preparation deadline", "resource budget", "metadata changed", "repository namespace changed", "directory namespace changed", "ambient link changed":
			e.Refusal = refusal.reason
		default:
			e.Refusal = "other-fixed-refusal"
		}
	}
	var exit *GitExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode
		e.ExitCode = &code
	}
	if deadline, ok := ctx.Deadline(); ok {
		n := time.Until(deadline).Nanoseconds()
		e.DeadlineRemainingNS = &n
	}
	return e
}

var d2Sink struct {
	sync.Mutex
	once          sync.Once
	file          *os.File
	bytes, events int
	truncated     bool
}

func d2Emit(e d2Event) {
	// Only callers carrying the fixed fixture context reach here. The runner's
	// trusted temporary directory is created by the diagnostic workflow.
	d2Sink.Lock()
	defer d2Sink.Unlock()
	d2Sink.once.Do(func() {
		dir := os.Getenv("HAMMERHEAD_D2_TRACE_DIR")
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
			fmt.Fprintln(os.Stderr, "D2_TRACE_UNAVAILABLE")
			return
		}
		for slot := 0; slot < 16; slot++ {
			f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("preparation-%02d.jsonl", slot)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				d2Sink.file = f
				return
			}
			if !errors.Is(err, os.ErrExist) {
				break
			}
		}
		fmt.Fprintln(os.Stderr, "D2_TRACE_UNAVAILABLE")
	})
	if d2Sink.file == nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if d2Sink.events >= 4096 || d2Sink.bytes+len(data) > 1<<20 {
		if !d2Sink.truncated {
			fmt.Fprintln(os.Stderr, "D2_TRACE_LIMIT")
			d2Sink.truncated = true
		}
		return
	}
	n, err := d2Sink.file.Write(data)
	d2Sink.bytes += n
	d2Sink.events++
	if err != nil {
		fmt.Fprintln(os.Stderr, "D2_TRACE_WRITE_ERROR")
	}
}
func d2Observe(ctx context.Context, stage string, start time.Time, err error) {
	if d2Active(ctx) {
		d2Emit(d2BuildEvent(ctx, stage, start, err))
	}
}

type d2ChildTrace struct {
	ctx, child          context.Context
	stage               string
	start               time.Time
	cmd                 *exec.Cmd
	stderr              *bytes.Buffer
	complete            atomic.Bool
	waitErr, cleanupErr error
}

func d2BeginChild(ctx, child context.Context, args []string) *d2ChildTrace {
	if !d2Active(ctx) {
		return nil
	}
	stage := "fixed-query"
	if len(args) > 0 {
		switch args[0] {
		case "config":
			stage = "config-no-includes"
		case "var":
			stage = "var-system-attributes"
		case "ls-files":
			stage = "whole-index"
		}
	}
	return &d2ChildTrace{ctx: ctx, child: child, stage: stage, start: time.Now()}
}
func d2StderrCategory(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	s := strings.ToLower(string(data))
	for _, item := range []struct{ needle, category string }{
		{"darwin_user_temp_dir", "darwin-temp-query-warning"}, {"operation not permitted", "operation-not-permitted"}, {"permission denied", "permission-denied"}, {"too many open files", "descriptor-exhaustion"},
		{"resource temporarily unavailable", "resource-unavailable"}, {"bad config", "bad-config"},
		{"unknown option", "unsupported-option"}, {"not a git repository", "not-repository"},
		{"fatal:", "fatal-other"},
	} {
		if strings.Contains(s, item.needle) {
			return item.category
		}
	}
	return "nonempty-other"
}
func (t *d2ChildTrace) finish(err error) {
	if t == nil {
		return
	}
	e := d2BuildEvent(t.ctx, t.stage, t.start, err)
	e.ChildContext = d2Category(t.child.Err())
	e.WaitCategory = d2Category(t.waitErr)
	e.CleanupCategory = d2Category(t.cleanupErr)
	// Wait completion publishes ProcessState and output buffers. Never inspect
	// them while os/exec's reader goroutines could still be writing.
	if t.complete.Load() {
		e.IOComplete = true
		if t.cmd.ProcessState != nil {
			code := t.cmd.ProcessState.ExitCode()
			e.ExitCode = &code
			if ws, ok := t.cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				e.Signal = int(ws.Signal())
			}
		}
		e.StderrBytes = t.stderr.Len()
		e.StderrCategory = d2StderrCategory(t.stderr.Bytes())
	}
	d2Emit(e)
}
