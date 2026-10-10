package git_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/git"
	"github.com/talarurus/hammerhead/internal/scanstate"
	"golang.org/x/sys/unix"
)

func TestGitSnapshot_RunnerQuietBranchDiagnostics(t *testing.T) {
	for _, query := range []struct {
		name  string
		args  []string
		kind  error
		state scanstate.GitBranchState
	}{
		{"symbolic-ref", []string{"symbolic-ref", "--quiet", "HEAD"}, git.ErrDetachedHEAD, scanstate.GitBranchDetached},
		{"show-ref", []string{"show-ref", "--verify", "--quiet", "refs/heads/main"}, git.ErrUnbornBranch, scanstate.GitBranchUnborn},
	} {
		t.Run(query.name, func(t *testing.T) {
			for _, diagnostic := range []struct{ name, stderr string }{
				{"empty", ""},
				{"LF", "\n"},
				{"CRLF", "\r\n"},
				{"space", " "},
				{"tab", "\t"},
				{"mixed-whitespace", " \t\r\n"},
				{"blank-lines", "\n\n"},
				{"unexpected", "secret_sentinel\n"},
				{"unknown-git-diagnostic", "fatal: unknown revision or path not in the working tree\n"},
			} {
				t.Run(diagnostic.name, func(t *testing.T) {
					root, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					bin := t.TempDir()
					// Exercise the actual runner (including captured stderr), typed
					// exit error and public snapshot collector with a trusted fixture.
					script := `#!/bin/sh
shift 5
printf '%s\n' "$*" >> .calls
if [ "$*" = "$(/bin/cat .query)" ]; then
    /bin/cat .stderr >&2
    exit 1
fi
case "$*" in
    'rev-parse --show-toplevel') pwd -P ;;
    'symbolic-ref --quiet HEAD') printf 'refs/heads/main\n' ;;
    'rev-parse --verify HEAD^{commit}') printf 'synthetic-object-id\n' ;;
    'status --porcelain=v1 -z --ignore-submodules=all') exit 0 ;;
    *) exit 128 ;;
esac
`
					for path, content := range map[string]string{
						filepath.Join(bin, "git"):      script,
						filepath.Join(root, ".query"):  strings.Join(query.args, " "),
						filepath.Join(root, ".stderr"): diagnostic.stderr,
					} {
						if err := os.WriteFile(path, []byte(content), 0700); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("PATH", bin)
					runner, err := git.NewGitRunner(root)
					if err != nil {
						t.Fatal(err)
					}
					_, err = runner.Run(context.Background(), root, query.args...)
					var exitErr *git.GitExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode != 1 || err.Error() != "git exited with code 1" {
						t.Fatalf("expected safe typed exit 1, got %v", err)
					}
					quiet := diagnostic.stderr == ""
					if errors.Is(err, query.kind) != quiet || (!quiet && exitErr.Kind != nil) {
						t.Fatalf("unexpected classification for %q: %v", diagnostic.stderr, exitErr.Kind)
					}
					s, err := git.CollectSnapshot(context.Background(), root)
					if s.Availability != scanstate.GitAvailable || s.Applicability != scanstate.GitRoot || s.ModifiedCount != 0 || s.UntrackedCount != 0 {
						t.Fatal(s, err)
					}
					if quiet {
						if err != nil || s.Status != scanstate.CheckStatusCompleted || s.BranchState != query.state {
							t.Fatal(s, err)
						}
					} else if !errors.As(err, &exitErr) || exitErr.ExitCode != 1 || exitErr.Kind != nil || err.Error() != "git exited with code 1" || s.Status != scanstate.CheckStatusPartial || s.BranchState != scanstate.GitBranchUnknown {
						t.Fatalf("diagnostic established branch state or leaked stderr: %v, %v", s, err)
					}
					calls, err := os.ReadFile(filepath.Join(root, ".calls"))
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(calls), "status --porcelain") != quiet {
						t.Fatalf("unexpected status collection: %s", calls)
					}
				})
			}
		})
	}
}

func snapshotGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}
func initSnapshotRepo(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshotGit(t, root, "init", "-b", "main")
	return root
}
func commitSnapshotRepo(t *testing.T, root string) {
	t.Helper()
	snapshotGit(t, root, "add", ".")
	snapshotGit(t, root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-m", "synthetic fixture")
}
func assertSnapshot(t *testing.T, root string, branch scanstate.GitBranchState) scanstate.GitSnapshot {
	t.Helper()
	s, err := git.CollectSnapshot(context.Background(), root)
	if err != nil || s.Availability != scanstate.GitAvailable || s.Applicability != scanstate.GitRoot || s.Status != scanstate.CheckStatusCompleted || s.BranchState != branch {
		t.Fatal(s, err)
	}
	return s
}

func TestGitUnavailable_NoFallbackRead(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink-to-outside-fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
				t.Fatal(err)
			}
			head := filepath.Join(root, ".git", "HEAD")
			if kind == "fifo" {
				if err := unix.Mkfifo(head, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				sentinel := filepath.Join(t.TempDir(), "outside-secret-sentinel")
				if err := unix.Mkfifo(sentinel, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(sentinel, head); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", t.TempDir())
			done := make(chan scanstate.GitSnapshot, 1)
			go func() {
				s, err := git.CollectSnapshot(context.Background(), root)
				if err != nil {
					s.Status = scanstate.CheckStatusFailed
				}
				done <- s
			}()
			select {
			case s := <-done:
				if s.Availability != scanstate.GitUnavailable || s.Status != scanstate.CheckStatusUnavailable || s.Applicability != scanstate.GitApplicabilityUnknown || s.BranchState != scanstate.GitBranchUnknown || s.Root != "" {
					t.Fatal(s)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("raw HEAD access blocked on FIFO")
			}
		})
	}
}

func TestGitSnapshot_RealBranchesAndIndexReadOnly(t *testing.T) {
	root := initSnapshotRepo(t)
	s := assertSnapshot(t, root, scanstate.GitBranchUnborn)
	if s.Branch != "main" || s.ModifiedCount != 0 || s.UntrackedCount != 0 {
		t.Fatal(s)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked"), []byte("synthetic content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commitSnapshotRepo(t, root)
	index := filepath.Join(root, ".git", "index")
	// A deliberately old index mtime would expose an optional refresh write.
	old := time.Unix(1500000000, 0)
	if err := os.Chtimes(index, old, old); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	statBefore, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	s = assertSnapshot(t, root, scanstate.GitBranchNormal)
	after, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	statAfter, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	if s.Branch != "main" || s.ModifiedCount != 0 || s.UntrackedCount != 0 || !bytes.Equal(before, after) || !statBefore.ModTime().Equal(statAfter.ModTime()) {
		t.Fatalf("snapshot %v; index modified", s)
	}
	snapshotGit(t, root, "tag", "main")
	s = assertSnapshot(t, root, scanstate.GitBranchNormal)
	if s.Branch != "main" {
		t.Fatal("ambiguous short ref changed branch", s)
	}
	snapshotGit(t, root, "checkout", "--detach")
	s = assertSnapshot(t, root, scanstate.GitBranchDetached)
	if s.Branch != "" {
		t.Fatal(s)
	}
}

func TestGitSnapshot_WorktreeGitfileAndAuditedSubdirectory(t *testing.T) {
	root := initSnapshotRepo(t)
	commitSnapshotRepo(t, root)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	worktree := filepath.Join(parent, "worktree with spaces\n")
	snapshotGit(t, root, "worktree", "add", "-b", "linked", worktree)
	s := assertSnapshot(t, worktree, scanstate.GitBranchNormal)
	marker, err := os.Stat(filepath.Join(worktree, ".git"))
	if err != nil || !marker.Mode().IsRegular() {
		t.Fatal(marker, err)
	}
	if s.Branch != "linked" || s.Root != worktree {
		t.Fatal(s)
	}
	sub := filepath.Join(worktree, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	// The whole tree is dirty, but subdirectory health must remain non-applicable.
	if err := os.WriteFile(filepath.Join(worktree, "outside-subdir"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = git.CollectSnapshot(context.Background(), sub)
	if err != nil || s.Status != scanstate.CheckStatusNotApplicable || s.Applicability != scanstate.GitSubdirectory || s.Root != worktree || s.UntrackedCount != 0 {
		t.Fatal(s, err)
	}
}

func TestGitSnapshot_RealRenameAndControlNames(t *testing.T) {
	root := initSnapshotRepo(t)
	oldName, newName := "source\n\tname", "destination\r\n -> name"
	if err := os.WriteFile(filepath.Join(root, oldName), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	commitSnapshotRepo(t, root)
	snapshotGit(t, root, "mv", "--", oldName, newName)
	for _, name := range []string{"new\nfile", "quote\" and\ttab"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := assertSnapshot(t, root, scanstate.GitBranchNormal)
	if s.ModifiedCount != 1 || s.UntrackedCount != 2 {
		t.Fatal(s)
	}
}

func TestGitSnapshot_RealCorruption(t *testing.T) {
	for _, kind := range []string{"config", "index", "branch-ref", "missing-object", "HEAD", "gitfile", "ancestor-HEAD"} {
		t.Run(kind, func(t *testing.T) {
			root := initSnapshotRepo(t)
			commitSnapshotRepo(t, root)
			switch kind {
			case "HEAD", "ancestor-HEAD":
				if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("invalid HEAD\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "ancestor-HEAD" {
					sub := filepath.Join(root, "sub")
					if err := os.Mkdir(sub, 0700); err != nil {
						t.Fatal(err)
					}
					root = sub
				}
			case "gitfile":
				root = t.TempDir()
				if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /nonexistent/synthetic-metadata\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "config":
				if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[broken\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "index":
				if err := os.WriteFile(filepath.Join(root, ".git", "index"), []byte("invalid index"), 0600); err != nil {
					t.Fatal(err)
				}
			case "branch-ref":
				if err := os.WriteFile(filepath.Join(root, ".git", "refs", "heads", "main"), []byte("invalid ref\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-object":
				if err := os.WriteFile(filepath.Join(root, ".git", "refs", "heads", "main"), []byte("1111111111111111111111111111111111111111\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, err := git.CollectSnapshot(context.Background(), root)
			if err == nil || s.Status != scanstate.CheckStatusPartial || s.Availability != scanstate.GitAvailable {
				t.Fatal(s, err)
			}
		})
	}
}
