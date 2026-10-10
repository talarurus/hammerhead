//go:build unix

package git_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/git"
)

// Both generations have an independent watchdog, even if the runner or the
// test fails. The descendant owns a lock so death can be checked even while an
// orphan is briefly a zombie awaiting its system reaper.
func runReview7DescendantHelper() {
	time.AfterFunc(15*time.Second, func() { os.Exit(90) })
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	if os.Args[len(os.Args)-1] == "--review7-child" {
		f, err := os.Create(".child_lock")
		if err != nil || syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			os.Exit(91)
		}
		defer f.Close()
		os.WriteFile(".child_group", []byte(strconv.Itoa(syscall.Getpgrp())), 0600)
		os.WriteFile(".child_ready", nil, 0600)
		for range term {
			os.WriteFile(".child_term_received", nil, 0600)
			// Deliberately survive SIGTERM without retaining the runner's pipes.
		}
		return
	}

	os.WriteFile(".pid", []byte(strconv.Itoa(os.Getpid())), 0600)
	exe, err := os.Executable()
	if err != nil {
		os.Exit(92)
	}
	child, err := os.StartProcess(exe, append(os.Args, "--review7-child"), &os.ProcAttr{
		Dir: ".", Env: os.Environ(), Files: nil,
	})
	if err != nil {
		os.Exit(93)
	}
	os.WriteFile(".child_pid", []byte(strconv.Itoa(child.Pid)), 0600)
	child.Release()
	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(".child_ready"); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			os.Exit(94)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.WriteFile(".started", nil, 0600)
	for {
		select {
		case <-term:
			os.WriteFile(".parent_term_received", nil, 0600)
			return // Exit promptly, leaving the stubborn child in the owned group.
		default:
			if stream, err := os.ReadFile(".overflow"); err == nil {
				if string(stream) == "stdout" {
					os.Stdout.Write(bytes.Repeat([]byte("a"), git.MaxStdoutBytes+1))
				} else {
					os.Stderr.Write(bytes.Repeat([]byte("b"), git.MaxStderrBytes+1))
				}
				<-term
				os.WriteFile(".parent_term_received", nil, 0600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func waitReview7File(t *testing.T, dir, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not create %s within 5s", name)
}

func readReview7PID(t *testing.T, dir, name string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid PID in %s: %q", name, data)
	}
	return pid
}

func TestGitRunner_StubbornDescendantShutdown(t *testing.T) {
	setupMockGit(t)
	for _, mode := range []string{"cancel", "stdout", "stderr", "overflow_cancel", "overflow_deadline"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".helper_cmd"), []byte("review7_descendant"), 0600); err != nil {
				t.Fatal(err)
			}
			runner, err := git.NewGitRunner(dir)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if mode == "overflow_deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			}
			done := make(chan error, 1)
			// Register cleanup before starting any helper. Only signal the test's
			// group while its descendant demonstrably still holds the lock.
			t.Cleanup(func() {
				cancel()
				data, err := os.ReadFile(filepath.Join(dir, ".pid"))
				pid, parseErr := strconv.Atoi(string(data))
				if err == nil && parseErr == nil && pid > 0 && pid != syscall.Getpgrp() {
					f, err := os.Open(filepath.Join(dir, ".child_lock"))
					if err == nil {
						if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
							_ = syscall.Kill(-pid, syscall.SIGKILL)
						} else {
							_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
						}
						f.Close()
					}
				}
				select {
				case <-done:
				case <-time.After(4 * time.Second):
				}
			})
			go func() {
				_, err := runner.Run(ctx, dir)
				done <- err
				close(done)
			}()
			waitReview7File(t, dir, ".started")
			parent := readReview7PID(t, dir, ".pid")
			child := readReview7PID(t, dir, ".child_pid")
			group := readReview7PID(t, dir, ".child_group")
			if group != parent || child == parent || group == syscall.Getpgrp() {
				t.Fatalf("expected distinct child in isolated parent's group: parent=%d child=%d group=%d", parent, child, group)
			}
			wantErr := error(context.Canceled)
			start := time.Now()
			if mode == "cancel" {
				cancel()
			} else {
				stream := mode
				if strings.HasPrefix(mode, "overflow_") {
					stream = "stderr"
				}
				if mode == "overflow_deadline" {
					deadline, _ := ctx.Deadline()
					// Trigger overflow just before the parent deadline, within the
					// stubborn descendant's mandatory TERM grace period.
					time.Sleep(time.Until(deadline) - 500*time.Millisecond)
					start = time.Now()
					wantErr = context.DeadlineExceeded
				} else if mode == "stdout" {
					wantErr = git.ErrStdoutLimit
				} else if mode == "stderr" {
					wantErr = git.ErrStderrLimit
				}
				if err := os.WriteFile(filepath.Join(dir, ".overflow"), []byte(stream), 0600); err != nil {
					t.Fatal(err)
				}
				waitReview7File(t, dir, ".parent_term_received")
				if mode == "overflow_cancel" {
					cancel() // Overflow already initiated cleanup; parent wins.
				}
			}
			select {
			case err := <-done:
				if !errors.Is(err, wantErr) {
					t.Fatalf("expected %v, got %v", wantErr, err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("runner exceeded bounded cleanup time")
			}
			elapsed := time.Since(start)
			f, err := os.Open(filepath.Join(dir, ".child_lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// Check immediately on return, without a post-return grace period.
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("descendant %d survived runner return: %v", child, err)
			}
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			if elapsed < time.Second || elapsed > 4*time.Second {
				t.Fatalf("expected bounded TERM grace before KILL, took %v", elapsed)
			}
			waitReview7File(t, dir, ".parent_term_received")
			waitReview7File(t, dir, ".child_term_received")
			assertHelperTerminated(t, dir)
		})
	}
}

func TestGitRunner_RelativePATHIsUnsafe(t *testing.T) {
	for _, entry := range []string{".", "bin"} {
		t.Run(entry, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.MkdirAll(entry, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(entry, "git"), []byte("target_secret_sentinel"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", entry)
			t.Setenv("GODEBUG", "execerrdot=1")
			if _, err := exec.LookPath("git"); !errors.Is(err, exec.ErrDot) {
				t.Fatalf("expected adversarial ErrDot fixture, got %v", err)
			}
			runner, err := git.NewGitRunner(".")
			if runner != nil || !errors.Is(err, git.ErrUnsafeGitPath) || errors.Is(err, git.ErrGitNotFound) {
				t.Fatalf("expected unsafe path without missing-Git fallback, got %v, %v", runner, err)
			}
			if strings.Contains(err.Error(), "target_secret_sentinel") {
				t.Fatalf("lookup error exposed target content: %v", err)
			}
			if err := os.Mkdir(".git", 0700); err != nil {
				t.Fatal(err)
			}
			info, err := git.DetectRepo(context.Background(), ".")
			if info != nil || !errors.Is(err, git.ErrUnsafeGitPath) {
				t.Fatalf("DetectRepo entered missing-Git fallback: %v, %v", info, err)
			}
			status, err := git.GetWorktreeStatus(context.Background(), ".")
			if status != nil || !errors.Is(err, git.ErrUnsafeGitPath) {
				t.Fatalf("GetWorktreeStatus entered missing-Git fallback: %v, %v", status, err)
			}
		})
	}
}

func TestGitRunner_GenuineMissingGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	runner, err := git.NewGitRunner(t.TempDir())
	if runner != nil || !errors.Is(err, git.ErrGitNotFound) {
		t.Fatalf("expected missing Git, got %v, %v", runner, err)
	}
	if _, err := git.DetectRepo(context.Background(), t.TempDir()); err != nil {
		t.Fatal(fmt.Errorf("missing-Git fallback failed: %w", err))
	}
}
