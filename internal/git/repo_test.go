package git_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/git"
)

func TestDetectRepo_NonGitDir(t *testing.T) {
	tempDir := t.TempDir()

	info, err := git.DetectRepo(tempDir)
	if err != nil {
		t.Fatalf("DetectRepo failed: %v", err)
	}
	if info.IsRepo {
		t.Errorf("expected tempDir without .git to not be a repo, got %+v", info)
	}
}

func TestDetectRepo_ValidGitDir(t *testing.T) {
	// The current hammerhead workspace is an initialized git repo
	info, err := git.DetectRepo(".")
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
	_, _ = git.GetWorktreeStatus(tempDir)

	// 5. Check if the sentinel file was created.
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("Git executed the malicious core.fsmonitor script! Sentinel file was created.")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat error: %v", err)
	}
}
