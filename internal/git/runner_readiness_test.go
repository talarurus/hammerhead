//go:build unix

package git_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/git"
)

// Readiness comes from the descendant after it owns the lock and inherited
// stdout/stderr. Startup time is outside the pipe-leak deadline under test.
func runReadyPipeHelper() {
	time.AfterFunc(15*time.Second, func() { os.Exit(90) })
	if os.Args[len(os.Args)-1] == "--ready-pipe-child" {
		lock, err := os.Create(".child_lock")
		if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			os.Exit(91)
		}
		defer lock.Close()
		if err := os.WriteFile(".child_group", []byte(strconv.Itoa(syscall.Getpgrp())), 0600); err != nil {
			os.Exit(92)
		}
		ready := os.NewFile(3, "ready")
		if _, err := ready.Write([]byte{1}); err != nil {
			os.Exit(93)
		}
		ready.Close()
		os.Stdout.Write([]byte("child_output\n"))
		select {} // Remain alive, holding both output pipes until group termination.
	}
	if err := os.WriteFile(".pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(94)
	}
	r, w, err := os.Pipe()
	if err != nil {
		os.Exit(95)
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(96)
	}
	child, err := os.StartProcess(exe, append(os.Args, "--ready-pipe-child"), &os.ProcAttr{
		Dir: ".", Env: os.Environ(), Files: []*os.File{os.Stdin, os.Stdout, os.Stderr, w},
	})
	if err != nil {
		os.Exit(97)
	}
	w.Close()
	if err := os.WriteFile(".child_pid", []byte(strconv.Itoa(child.Pid)), 0600); err != nil {
		os.Exit(98)
	}
	child.Release()
	var ready [1]byte
	if _, err := io.ReadFull(r, ready[:]); err != nil || ready[0] != 1 {
		os.Exit(99)
	}
	r.Close()
	if err := os.WriteFile(".started", nil, 0600); err != nil {
		os.Exit(100)
	}
	// This is a barrier, not a delay: the test releases the leader only after
	// observing readiness and verifying the live descendant's group and lock.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		if _, err := os.Stat(".release"); err == nil {
			os.Exit(0)
		}
	}
}

func TestGitRunner_DescendantPipeCleanup(t *testing.T) {
	setupMockGit(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".helper_cmd"), []byte("descendant_pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	runner, err := git.NewGitRunner(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Parent watchdog bounds startup as well as runner cleanup. The command's
	// WaitDelay supplies the pipe timeout after the ready leader exits.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			// Last-resort cleanup only while this fixture's descendant still
			// owns its lock in the isolated leader group.
			data, _ := os.ReadFile(filepath.Join(dir, ".pid"))
			pid, _ := strconv.Atoi(string(data))
			lock, err := os.Open(filepath.Join(dir, ".child_lock"))
			if err == nil {
				if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil && pid > 0 && pid != syscall.Getpgrp() {
					syscall.Kill(-pid, syscall.SIGKILL)
				} else {
					syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
				}
				lock.Close()
			}
			t.Error("runner did not finish during watchdog cleanup")
		}
	})
	go func() {
		_, err := runner.RunTrustedFixture(ctx, dir)
		done <- err
		close(done)
	}()
	waitReview7File(t, dir, ".started")
	parent := readReview7PID(t, dir, ".pid")
	child := readReview7PID(t, dir, ".child_pid")
	group := readReview7PID(t, dir, ".child_group")
	lock, err := os.Open(filepath.Join(dir, ".child_lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if parent != group || child == parent || group == syscall.Getpgrp() {
		t.Fatalf("descendant must share an isolated leader's group: parent=%d child=%d group=%d", parent, child, group)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("readiness was published before descendant owned its lock")
	}
	if err := os.WriteFile(filepath.Join(dir, ".release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, git.ErrGitTimeout) {
			t.Fatalf("expected inherited-pipe timeout after leader exit, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runner exceeded pipe timeout plus group cleanup allowance")
	}
	// No post-return sleep/grace: cleanup must have released the lock already.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("descendant %d survived runner return: %v", child, err)
	}
	syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	assertHelperTerminated(t, dir)
}
