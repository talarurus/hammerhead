package git_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/git"
)

func TestMain(m *testing.M) {
	isHelper := false
	for _, arg := range os.Args {
		if arg == "--no-pager" {
			isHelper = true
		}
	}

	if isHelper {
		cmdBytes, _ := os.ReadFile(".helper_cmd")
		cmd := strings.TrimSpace(string(cmdBytes))
		switch cmd {
		case "review7_descendant":
			runReview7DescendantHelper()
		case "cancel_before_start":
			os.WriteFile(".started", []byte("yes"), 0644)
			os.Exit(0)
		case "cancel_active":
			os.WriteFile(".started", []byte("yes"), 0644)
			time.Sleep(15 * time.Second)
		case "force_kill_watchdog":
			os.WriteFile(".pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			go func() {
				for range c {
					os.WriteFile(".term_received", []byte("yes"), 0644)
				}
			}()
			// Readiness means SIGTERM is intercepted and the observer is running.
			os.WriteFile(".started", []byte("yes"), 0644)
			time.Sleep(15 * time.Second)
		case "stderr_secret":
			os.Stderr.Write([]byte("secret_sentinel\n"))
			os.Exit(1)
		case "not_a_repo":
			os.Stderr.Write([]byte("fatal: not a git repository (or any of the parent directories): .git\n"))
			os.Exit(128)
		case "timeout":
			os.WriteFile(".pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			time.Sleep(15 * time.Second)
		case "stdout_limit":
			os.WriteFile(".pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			go func() {
				<-c
				os.WriteFile(".term_received", []byte("yes"), 0644)
			}()
			limit := 4 * 1024 * 1024
			buf := bytes.Repeat([]byte("a"), limit+1)
			os.Stdout.Write(buf)
			// Wait to be killed by the runner's cancellation
			time.Sleep(15 * time.Second)
		case "stderr_limit":
			os.WriteFile(".pid", []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGTERM)
			go func() {
				<-c
				os.WriteFile(".term_received", []byte("yes"), 0644)
			}()
			limit := 64 * 1024
			buf := bytes.Repeat([]byte("b"), limit+1)
			os.Stderr.Write(buf)
			// Wait to be killed by the runner's cancellation
			time.Sleep(15 * time.Second)
		case "exact_limit":
			limit := 4 * 1024 * 1024
			buf := bytes.Repeat([]byte("a"), limit)
			os.Stdout.Write(buf)
			os.Exit(0)
		case "exact_stderr_limit":
			limit := 64 * 1024
			buf := bytes.Repeat([]byte("b"), limit)
			os.Stderr.Write(buf)
			os.Exit(0)
		case "environment":
			for _, e := range os.Environ() {
				fmt.Println(e)
			}
			os.Exit(0)
		case "descendant_no_pipe":
			if _, err := os.Stat(".is_child"); os.IsNotExist(err) {
				os.WriteFile(".is_child", nil, 0644)
				exe, _ := os.Executable()
				p, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
					Env:   os.Environ(),
					Files: nil,
					Dir:   ".",
				})
				if err == nil {
					os.WriteFile(".child_pid", []byte(fmt.Sprintf("%d", p.Pid)), 0644)
					p.Release()
				}
				// Wait for child to create lock file before exiting
				for i := 0; i < 50; i++ {
					if _, err := os.Stat(".child_lock"); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				os.Exit(0) // Parent exits
			}
			// child process
			f, _ := os.Create(".child_lock")
			syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			time.Sleep(15 * time.Second)
		case "descendant_pipe":
			if _, err := os.Stat(".is_child"); os.IsNotExist(err) {
				os.WriteFile(".is_child", nil, 0644)
				exe, _ := os.Executable()
				p, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
					Env:   os.Environ(),
					Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
					Dir:   ".",
				})
				if err == nil {
					os.WriteFile(".child_pid", []byte(fmt.Sprintf("%d", p.Pid)), 0644)
					p.Release()
				} else {
					os.WriteFile(".child_err", []byte(err.Error()), 0644)
				}
				os.Exit(0) // Parent exits immediately
			}
			// child process
			f, _ := os.Create(".child_lock")
			syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			os.Stdout.Write([]byte("child_output\n"))
			time.Sleep(15 * time.Second)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func setupMockGit(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	gitPath := filepath.Join(binDir, "git")
	err = os.Symlink(exe, gitPath)
	if err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() {
		os.Setenv("PATH", oldPath)
	})

	os.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Cleanup(func() {
		os.Unsetenv("GO_WANT_HELPER_PROCESS")
	})

	return binDir
}

func TestGitRunner_RejectTargetExecutable(t *testing.T) {
	for _, name := range []string{
		"direct", "dotdot_prefix_child", "outward_file_alias", "outward_directory_alias",
		"inward_file_alias", "inward_directory_alias", "alias_chain_outward", "target_alias",
		"external_sibling", "external_alias",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			inside := filepath.Join(target, "bin")
			outside := filepath.Join(root, "target-sibling")
			for _, dir := range []string{inside, outside} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			externalGit := filepath.Join(outside, "git")
			if err := os.WriteFile(externalGit, []byte("must never execute"), 0755); err != nil {
				t.Fatal(err)
			}
			link := func(dest, alias string) {
				t.Helper()
				if err := os.Symlink(dest, alias); err != nil {
					t.Fatal(err)
				}
			}
			pathDir := inside
			wantUnsafe := true
			switch name {
			case "direct", "inward_file_alias", "inward_directory_alias", "target_alias":
				if err := os.WriteFile(filepath.Join(inside, "git"), []byte("must never execute"), 0755); err != nil {
					t.Fatal(err)
				}
				if name == "inward_file_alias" {
					pathDir = filepath.Join(root, "alias-bin")
					if err := os.Mkdir(pathDir, 0755); err != nil {
						t.Fatal(err)
					}
					link(filepath.Join(inside, "git"), filepath.Join(pathDir, "git"))
				} else if name == "inward_directory_alias" {
					pathDir = filepath.Join(root, "alias-bin")
					link(inside, pathDir)
				} else if name == "target_alias" {
					alias := filepath.Join(root, "target-alias")
					link(target, alias)
					target = alias
				}
			case "dotdot_prefix_child":
				pathDir = filepath.Join(target, "..bin")
				if err := os.Mkdir(pathDir, 0755); err != nil {
					t.Fatal(err)
				}
				link(externalGit, filepath.Join(pathDir, "git"))
			case "outward_file_alias", "alias_chain_outward":
				link(externalGit, filepath.Join(inside, "git"))
				if name == "alias_chain_outward" {
					pathDir = filepath.Join(root, "alias-bin")
					if err := os.Mkdir(pathDir, 0755); err != nil {
						t.Fatal(err)
					}
					link(filepath.Join(inside, "git"), filepath.Join(pathDir, "git"))
				}
			case "outward_directory_alias":
				pathDir = filepath.Join(target, "alias-bin")
				link(outside, pathDir)
			case "external_sibling":
				pathDir, wantUnsafe = outside, false
			case "external_alias":
				pathDir, wantUnsafe = filepath.Join(root, "external-alias"), false
				link(outside, pathDir)
			}
			t.Setenv("PATH", pathDir)
			runner, err := git.NewGitRunner(target)
			if wantUnsafe {
				if runner != nil || !errors.Is(err, git.ErrUnsafeGitPath) {
					t.Fatalf("expected ErrUnsafeGitPath and no runner, got %v, %v", runner, err)
				}
			} else if err != nil || runner == nil {
				t.Fatalf("expected external executable to be trusted, got %v, %v", runner, err)
			}
		})
	}
}

func assertHelperTerminated(t *testing.T, dir string) {
	t.Helper()
	pidBytes, err := os.ReadFile(filepath.Join(dir, ".pid"))
	if err != nil {
		t.Fatalf("reading helper PID: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid helper PID %q", pidBytes)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("helper %d still exists after cleanup: %v", pid, err)
	}
}

func TestGitRunner_Timeout(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("timeout"), 0644); err != nil {
		t.Fatal(err)
	}

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = runner.Run(context.Background(), targetDir)
	elapsed := time.Since(start)
	if !errors.Is(err, git.ErrGitTimeout) {
		t.Fatalf("expected ErrGitTimeout, got %v", err)
	}
	if elapsed < 10*time.Second || elapsed > 13*time.Second {
		t.Fatalf("expected independent 10s deadline with bounded cleanup, took %v", elapsed)
	}
	assertHelperTerminated(t, targetDir)
}

func TestGitRunner_StdoutLimit(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("stdout_limit"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runner.Run(context.Background(), targetDir)
	if !errors.Is(err, git.ErrStdoutLimit) {
		t.Fatalf("expected ErrStdoutLimit, got %v", err)
	}

	// Verify child PID is recorded and it was killed
	pidBytes, err := os.ReadFile(filepath.Join(targetDir, ".pid"))
	if err != nil {
		t.Fatalf("failed to read child PID: %v", err)
	}
	var pid int
	fmt.Sscanf(string(pidBytes), "%d", &pid)

	process, err := os.FindProcess(pid)
	if err == nil {
		err = process.Signal(syscall.Signal(0))
		if err == nil {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("process was not killed after overflow")
		}
	}
}

func TestGitRunner_StderrLimit(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("stderr_limit"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runner.Run(context.Background(), targetDir)
	if !errors.Is(err, git.ErrStderrLimit) {
		t.Fatalf("expected ErrStderrLimit, got %v", err)
	}

	// Verify child PID is recorded and it was killed
	pidBytes, err := os.ReadFile(filepath.Join(targetDir, ".pid"))
	if err != nil {
		t.Fatalf("failed to read child PID: %v", err)
	}
	var pid int
	fmt.Sscanf(string(pidBytes), "%d", &pid)

	process, err := os.FindProcess(pid)
	if err == nil {
		err = process.Signal(syscall.Signal(0))
		if err == nil {
			err = process.Signal(syscall.Signal(0))
			if err == nil {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatal("process was not killed after overflow")
			}
		}
	}
}

func TestGitRunner_ExactLimit(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("exact_limit"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runner.Run(context.Background(), targetDir)
	if err != nil {
		t.Fatalf("expected success on exact limit, got %v", err)
	}
	if len(out) != 4*1024*1024 {
		t.Fatalf("expected exactly 4MiB output, got %d", len(out))
	}
}

func TestGitRunner_ExactStderrLimit(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("exact_stderr_limit"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runner.Run(context.Background(), targetDir)
	if err != nil {
		t.Fatalf("expected success on exact stderr limit, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 stdout output, got %d", len(out))
	}
}

func TestGitRunner_Environment(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("environment"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runner.Run(context.Background(), targetDir)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "GIT_OPTIONAL_LOCKS=0") {
		t.Error("missing GIT_OPTIONAL_LOCKS=0")
	}
	if !strings.Contains(out, "LC_ALL=C") {
		t.Error("missing LC_ALL=C")
	}
	if !strings.Contains(out, "GIT_CONFIG_GLOBAL=/dev/null") {
		t.Error("missing GIT_CONFIG_GLOBAL=/dev/null")
	}
}

func TestGitRunner_DescendantPipeCleanup(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("descendant_pipe"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = runner.Run(ctx, targetDir)
	if !errors.Is(err, git.ErrGitTimeout) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ErrGitTimeout, got %v", err)
	}

	// Verify child PID is recorded
	pidBytes, err := os.ReadFile(filepath.Join(targetDir, ".child_pid"))
	if err != nil {
		t.Fatalf("failed to read child PID: %v", err)
	}

	var pid int
	fmt.Sscanf(string(pidBytes), "%d", &pid)

	t.Cleanup(func() {
		lockFile := filepath.Join(targetDir, ".child_lock")
		f, err := os.OpenFile(lockFile, os.O_RDWR, 0666)
		if err == nil {
			errLock := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if errLock != nil {
				syscall.Kill(pid, syscall.SIGKILL)
			} else {
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			}
			f.Close()
		} else {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	// Use Flock to verify process is dead
	lockFile := filepath.Join(targetDir, ".child_lock")
	f, err := os.OpenFile(lockFile, os.O_RDWR, 0666)
	if err == nil {
		defer f.Close()
	}

	dead := false
	var lastErr error
	for i := 0; i < 50; i++ {
		if err == nil {
			errLock := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			lastErr = errLock
			if errLock == nil {
				dead = true
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				break
			}
		} else {
			f, err = os.OpenFile(lockFile, os.O_RDWR, 0666)
			if err == nil {
				defer f.Close()
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !dead {
		t.Fatalf("descendant process was not terminated by cleanup, lastErr: %v", lastErr)
	}
}

func TestGitRunner_CancelActive(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("cancel_active"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cleanup

	startedFile := filepath.Join(targetDir, ".started")

	// Run in a separate goroutine so we can wait for .started
	errCh := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, targetDir)
		errCh <- err
	}()

	// Bounded wait for the helper to start
	timeout := time.After(5 * time.Second)
	started := false
waitStart:
	for {
		select {
		case <-timeout:
			break waitStart
		default:
			if _, err := os.Stat(startedFile); err == nil {
				started = true
				break waitStart
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if !started {
		t.Fatal("expected process to have started within 5s")
	}

	// Trigger cancellation
	cancel()

	// Wait for runner to return
	select {
	case err := <-errCh:
		if !errors.Is(err, git.ErrGitCanceled) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected ErrGitCanceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner.Run did not return within 5s after cancellation")
	}
}

func TestGitRunner_ForceKill(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("force_kill_watchdog"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cleanup

	startedFile := filepath.Join(targetDir, ".started")

	errCh := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, targetDir)
		errCh <- err
	}()

	// Wait for start
	timeout := time.After(5 * time.Second)
	started := false
waitStart:
	for {
		select {
		case <-timeout:
			break waitStart
		default:
			if _, err := os.Stat(startedFile); err == nil {
				started = true
				break waitStart
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if !started {
		t.Fatal("expected process to have started within 5s")
	}

	// Measure the grace period from cancellation, after helper readiness.
	start := time.Now()
	cancel()

	// Wait for runner to return
	select {
	case err := <-errCh:
		if !errors.Is(err, git.ErrGitCanceled) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancel error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner.Run did not return within 5s after cancellation")
	}

	duration := time.Since(start)
	if duration < 1*time.Second {
		t.Fatalf("expected run to take at least 1s due to grace period, took %v", duration)
	}

	// Prove TERM was received
	if _, err := os.Stat(filepath.Join(targetDir, ".term_received")); err != nil {
		t.Fatalf("expected helper to receive SIGTERM before SIGKILL: %v", err)
	}

	assertHelperTerminated(t, targetDir)
}

func TestGitRunner_StderrSecret(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("stderr_secret"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runner.Run(context.Background(), targetDir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if strings.Contains(err.Error(), "secret_sentinel") {
		t.Fatalf("error message leaked stderr: %v", err)
	}

	var exitErr *git.GitExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode != 1 {
		t.Fatalf("expected GitExitError with code 1, got %v", err)
	}
}

func TestGitRunner_NotARepo(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("not_a_repo"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runner.Run(context.Background(), targetDir, "rev-parse", "--show-toplevel")
	if !errors.Is(err, git.ErrNotARepository) {
		t.Fatalf("expected ErrNotARepository, got %v", err)
	}
}

func TestGitRunner_DescendantNoPipeCleanup(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("descendant_no_pipe"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = runner.Run(ctx, targetDir)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	pidBytes, err := os.ReadFile(filepath.Join(targetDir, ".child_pid"))
	if err != nil {
		t.Fatalf("failed to read child PID: %v", err)
	}

	var pid int
	fmt.Sscanf(string(pidBytes), "%d", &pid)

	t.Cleanup(func() {
		lockFile := filepath.Join(targetDir, ".child_lock")
		f, err := os.OpenFile(lockFile, os.O_RDWR, 0666)
		if err == nil {
			errLock := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if errLock != nil {
				syscall.Kill(pid, syscall.SIGKILL)
			} else {
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			}
			f.Close()
		} else {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	lockFile := filepath.Join(targetDir, ".child_lock")
	f, err := os.OpenFile(lockFile, os.O_RDWR, 0666)
	if err == nil {
		defer f.Close()
	}

	dead := false
	var lastErr error
	for i := 0; i < 50; i++ {
		if err == nil {
			errLock := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			lastErr = errLock
			if errLock == nil {
				dead = true
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				break
			}
		} else {
			f, err = os.OpenFile(lockFile, os.O_RDWR, 0666)
			if err == nil {
				defer f.Close()
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !dead {
		t.Fatalf("descendant process %d was not terminated by cleanup, lastErr: %v", pid, lastErr)
	}
}

func TestGitRunner_CancelBeforeStart(t *testing.T) {
	setupMockGit(t)
	targetDir := t.TempDir()
	os.WriteFile(filepath.Join(targetDir, ".helper_cmd"), []byte("cancel_before_start"), 0644)

	runner, err := git.NewGitRunner(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before run

	_, err = runner.Run(ctx, targetDir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(targetDir, ".started")); err == nil {
		t.Fatal("process was started despite pre-cancellation")
	}
}
