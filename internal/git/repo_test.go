package git_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/git"
)

func TestDetectRepo_NonGitDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")

	info, err := git.DetectRepo(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("DetectRepo failed: %v", err)
	}
	if info.IsRepo {
		t.Errorf("expected tempDir without .git to not be a repo, got %+v", info)
	}
}

func TestDetectRepo_ValidGitDir(t *testing.T) {
	// The current hammerhead workspace is an initialized git repo
	info, err := git.DetectRepo(context.Background(), ".")
	if err != nil {
		t.Fatalf("DetectRepo on workspace failed: %v", err)
	}
	if !info.IsRepo {
		t.Errorf("expected current repo to be detected as git repo, got %+v", info)
	}
	if info.Root == "" {
		t.Errorf("expected non-empty repo root")
	}
}

func TestDetectRepo_SimulatedGitDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/feature-sec\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := git.DetectRepoFallback(tempDir)
	if err != nil {
		t.Fatalf("DetectRepoFallback failed: %v", err)
	}
	if !info.IsRepo {
		t.Errorf("expected simulated git dir to be recognized as repo")
	}
	if info.Branch != "feature-sec" {
		t.Errorf("expected branch feature-sec, got %q", info.Branch)
	}
}

func TestGitCommand_SubprocessInjection(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")

	// 1. Initialize a real Git repository in the temp directory.
	cmd := exec.Command("git", "init")
	cmd.Dir = tempDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git init failed: %v", err)
	}

	// 2. Create a malicious script.
	sentinel := filepath.Join(tempDir, "pwned.txt")
	scriptPath := filepath.Join(tempDir, "malicious.sh")
	scriptContent := fmt.Sprintf("#!/bin/sh\necho 'pwned' > %s\n", sentinel)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0o700); err != nil {
		t.Fatalf("writing malicious script: %v", err)
	}

	// 3. Configure git core.fsmonitor to execute the malicious script.
	cmd = exec.Command("git", "config", "core.fsmonitor", scriptPath)
	cmd.Dir = tempDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git config failed: %v", err)
	}

	// 4. Trigger Hammerhead's Git status function (which calls gitCommand).
	_, _ = git.GetWorktreeStatus(context.Background(), tempDir)

	// 5. Check if the sentinel file was created.
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("Git executed the malicious core.fsmonitor script! Sentinel file was created.")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat error: %v", err)
	}
}

func TestGetWorktreeStatus_SubmoduleIgnore(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	runGit := func(dir string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit(tempDir, "init")

	subDir := t.TempDir()
	runGit(subDir, "init")

	if err := os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(subDir, "add", "file.txt")
	runGit(subDir, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init")
	runGit(tempDir, "-c", "protocol.file.allow=always", "submodule", "add", subDir, "sub")
	runGit(tempDir, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "add submodule")
	if status := runGit(tempDir, "status", "--porcelain", "--ignore-submodules=none"); status != "" {
		t.Fatalf("expected clean initial worktree, got %q", status)
	}

	checkout := filepath.Join(tempDir, "sub")
	if err := os.WriteFile(filepath.Join(checkout, "file.txt"), []byte("dirty"), 0644); err != nil {
		t.Fatal(err)
	}
	if status := runGit(checkout, "status", "--porcelain"); status != "M file.txt" {
		t.Fatalf("expected modified checked-out submodule, got %q", status)
	}
	if status := runGit(tempDir, "status", "--porcelain", "--ignore-submodules=none"); status != "M sub" {
		t.Fatalf("expected parent to report dirty submodule, got %q", status)
	}

	info, err := git.GetWorktreeStatus(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("GetWorktreeStatus failed: %v", err)
	}

	if info.IsDirty || info.ModifiedCount != 0 || info.UntrackedCount != 0 {
		t.Fatalf("expected submodule modifications to be ignored, got %+v", info)
	}
}
