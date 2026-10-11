//go:build darwin || linux

package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/scanstate"
	"golang.org/x/sys/unix"
)

// The trusted helper is only a scheduling barrier. The controller alone mutates
// owned roots. FIFO readiness/release supplies ordering without timing sleeps.
func TestA2R1_CLIHandoff(t *testing.T) {
	for _, kind := range []string{"unchanged", "alias", "alias-symlink", "alias-directory", "symlink", "directory", "rename", "restored", "ancestor-restored", "minimal-symlink", "minimal-directory"} {
		for _, format := range []string{"json", "terminal", "quiet"} {
			minimal := strings.HasPrefix(kind, "minimal-")
			if minimal && format != "json" {
				continue
			}
			for _, threshold := range []string{"none", "high"} {
				retainedCases := []bool{false, true}
				if minimal {
					retainedCases = []bool{false}
				}
				for _, retained := range retainedCases {
					t.Run(fmt.Sprintf("%s/%s/%s/retained=%t", kind, format, threshold, retained), func(t *testing.T) {
						base := t.TempDir()
						parent := filepath.Join(base, "parent")
						root := filepath.Join(parent, "root")
						outside := filepath.Join(base, "outside")
						bin := filepath.Join(base, "bin")
						for _, p := range []string{root, outside, bin} {
							if err := os.MkdirAll(p, 0700); err != nil {
								t.Fatal(err)
							}
						}
						write := func(path, data string) {
							t.Helper()
							if err := os.WriteFile(path, []byte(data), 0600); err != nil {
								t.Fatal(err)
							}
						}
						for name, data := range map[string]string{"README.md": "synthetic", "LICENSE": "synthetic", ".gitignore": ".env\n*.key\nid_*\n", "probe.txt": "ordinary text\n", "a.key": "synthetic filename observation\n", "original.txt": "-----BEGIN PRIVATE KEY-----\nORIGINAL SYNTHETIC HEADER ONLY\n", "excluded.txt": "-----BEGIN PRIVATE KEY-----\nEXCLUDED SYNTHETIC HEADER ONLY\n"} {
							write(filepath.Join(root, name), data)
						}
						write(filepath.Join(outside, "probe.txt"), "-----BEGIN PRIVATE KEY-----\nOUTSIDE SYNTHETIC HEADER ONLY\n")
						if err := os.Symlink("original.txt", filepath.Join(root, "relative.txt")); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("excluded.txt", filepath.Join(root, "excluded-alias.txt")); err != nil {
							t.Fatal(err)
						}
						// Convert a previously eligible alias into an excluded target while Git is
						// blocked: reader target policy must still apply across the handoff.
						if err := os.Symlink("probe.txt", filepath.Join(root, "late-alias.txt")); err != nil {
							t.Fatal(err)
						}
						if !retained {
							if err := os.Remove(filepath.Join(root, "a.key")); err != nil {
								t.Fatal(err)
							}
							write(filepath.Join(root, "original.txt"), "ordinary synthetic text\n")
						}
						if minimal {
							for _, name := range []string{"original.txt", "relative.txt", "excluded.txt", "excluded-alias.txt", "late-alias.txt", "README.md", "LICENSE", ".gitignore"} {
								if err := os.Remove(filepath.Join(root, name)); err != nil {
									t.Fatal(err)
								}
							}
						}
						selected := root
						if strings.HasPrefix(kind, "alias") {
							selected = filepath.Join(base, "selected")
							if err := os.Symlink(root, selected); err != nil {
								t.Fatal(err)
							}
						}
						fifo := func(name string) *os.File {
							t.Helper()
							p := filepath.Join(base, name)
							if err := unix.Mkfifo(p, 0600); err != nil {
								t.Fatal(err)
							}
							f, err := os.OpenFile(p, os.O_RDWR, 0600)
							if err != nil {
								t.Fatal(err)
							}
							t.Cleanup(func() { f.Close() })
							return f
						}
						ready, release := fifo("ready"), fifo("release")
						quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
						script := fmt.Sprintf("#!/bin/sh\nprintf 'ready\\n' > %s\nread token < %s\nprintf 'fatal: not a git repository (or any of the parent directories): .git\\n' >&2\nexit 128\n", quote(ready.Name()), quote(release.Name()))
						if kind == "directory" || kind == "restored" || kind == "ancestor-restored" {
							script = fmt.Sprintf("#!/bin/sh\ncase \"$*\" in\n*'rev-parse --show-toplevel') printf 'ready\\n' > %s; read token < %s; printf '%%s\\n' %s;;\n*'symbolic-ref --quiet HEAD') printf 'refs/heads/main\\n';;\n*'show-ref --verify --quiet refs/heads/main') exit 1;;\n*'status --porcelain=v1 -z --ignore-submodules=all') printf '?? synthetic\\000';;\n*) exit 128;;\nesac\n", quote(ready.Name()), quote(release.Name()), quote(root))
						}
						if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0700); err != nil {
							t.Fatal(err)
						}
						ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
						defer cancel()
						args := []string{"audit", selected, "--fail-on", threshold, "--exclude", "excluded.txt"}
						if format == "quiet" {
							args = append(args, "--quiet")
						} else {
							args = append(args, "--output", format)
						}
						cmd := exec.CommandContext(ctx, binaryPath, args...)
						cmd.WaitDelay = time.Second
						cmd.Env = append(os.Environ(), "PATH="+bin, "NO_COLOR=1")
						var out, diag bytes.Buffer
						cmd.Stdout, cmd.Stderr = &out, &diag
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						done := make(chan error, 1)
						go func() { done <- cmd.Wait() }()
						// Always release/reap on fixture failure; no orphan helper or scan process.
						finished := false
						defer func() {
							release.Write([]byte("release\n"))
							cancel()
							if !finished {
								select {
								case <-done:
								case <-time.After(3 * time.Second):
									t.Error("scan watchdog cleanup failed")
								}
							}
						}()
						readyResult := make(chan error, 1)
						go func() { _, err := bufio.NewReader(ready).ReadString('\n'); readyResult <- err }()
						select {
						case err := <-readyResult:
							if err != nil {
								t.Fatal(err)
							}
						case err := <-done:
							finished = true
							t.Fatalf("scan ended before barrier: %v", err)
						case <-ctx.Done():
							t.Fatal("Git barrier watchdog fired")
						}
						if !minimal {
							if err := os.Remove(filepath.Join(root, "late-alias.txt")); err != nil {
								t.Fatal(err)
							}
							if err := os.Symlink("excluded.txt", filepath.Join(root, "late-alias.txt")); err != nil {
								t.Fatal(err)
							}
						}
						if kind != "unchanged" && kind != "alias" {
							moved := root
							if kind == "ancestor-restored" {
								moved = parent
							}
							if err := os.Rename(moved, moved+"-original"); err != nil {
								t.Fatal(err)
							}
							switch kind {
							case "symlink", "alias-symlink", "minimal-symlink":
								if err := os.Symlink(outside, root); err != nil {
									t.Fatal(err)
								}
							case "directory", "alias-directory", "minimal-directory":
								if err := os.Rename(outside, root); err != nil {
									t.Fatal(err)
								}
							case "restored", "ancestor-restored":
								if err := os.Rename(moved+"-original", moved); err != nil {
									t.Fatal(err)
								}
							}
						}
						if _, err := release.Write([]byte("release\n")); err != nil {
							t.Fatal(err)
						}
						var err error
						select {
						case err = <-done:
							finished = true
						case <-ctx.Done():
							t.Fatal("scan watchdog fired")
						}
						code := 0
						if err != nil {
							var exit *exec.ExitError
							if !errors.As(err, &exit) {
								t.Fatal(err)
							}
							code = exit.ExitCode()
						}
						changed := kind != "unchanged" && kind != "alias"
						want := 0
						if changed {
							want = 2
						} else if threshold == "high" && retained {
							want = 1
						}
						if code != want {
							t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", code, want, out.String(), diag.String())
						}
						if format == "json" {
							r := integratedJSON(t, out.Bytes())
							status := scanstate.StatusCompleted
							if changed {
								status = scanstate.StatusPartial
							}
							if r.Status != status || r.Coverage.Traversal.InventoryComplete == nil || !*r.Coverage.Traversal.InventoryComplete {
								t.Fatalf("original inventory/status lost: %+v", r)
							}
							original, relative, earlier := false, false, false
							for _, f := range r.Findings {
								if f.RuleID == "SEC-001" {
									switch f.Path {
									case "original.txt":
										original = true
									case "relative.txt":
										relative = true
									default:
										t.Fatalf("outside/excluded content observed: %+v", f)
									}
								}
								earlier = earlier || f.RuleID == "FILE-001" && f.Path == "a.key"
								if changed && f.RuleID == "GIT-002" {
									t.Fatalf("inconsistent Git facts retained: %+v", f)
								}
							}
							if original != retained || relative != retained || earlier != retained {
								t.Fatalf("native findings lost: %+v", r.Findings)
							}
							gitPartial := false
							for _, c := range r.Coverage.Checks {
								if c.RuleID == "GIT-002" {
									gitPartial = c.Status == scanstate.CheckStatusPartial
								}
							}
							reason := false
							for _, r := range r.Coverage.Reasons {
								reason = reason || r.Code == scanstate.ReasonGitFailure && r.Count > 0
							}
							if gitPartial != changed || reason != changed {
								t.Fatalf("Git scope classification: %+v", r.Coverage)
							}
						} else {
							if retained && (!strings.Contains(out.String(), "[FILE-001]") || !strings.Contains(out.String(), "original.txt") || !strings.Contains(out.String(), "relative.txt")) {
								t.Fatalf("native report lost: %s", out.String())
							}
							if strings.Contains(out.String(), "probe.txt") || strings.Contains(out.String(), "late-alias.txt") {
								t.Fatalf("outside/excluded observation: %s", out.String())
							}
							if !retained && format == "quiet" && out.Len() != 0 {
								t.Fatalf("zero finding quiet output: %s", out.String())
							}
							stream := out.String()
							if format == "quiet" {
								stream = diag.String()
							}
							if changed && (!strings.Contains(stream, "PARTIAL") || !strings.Contains(strings.ToUpper(stream), "COVERAGE")) {
								t.Fatalf("incomplete report hidden: %s", stream)
							}
						}
					})
				}
			}
		}
	}
}

// A deep, otherwise ordinary root forces observer setup to exhaust only its
// ancestor-descriptor allowance. Traversal and native reads need few handles.
// The limit belongs to the CLI child; the test runner retains its own limits.
func TestA2R1_ObserverFailureVisible(t *testing.T) {
	for _, format := range []string{"json", "terminal", "quiet"} {
		for _, retained := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retained=%t", format, retained), func(t *testing.T) {
				root := t.TempDir()
				for i := 0; i < 48; i++ {
					root = filepath.Join(root, "d")
				}
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string]string{"README.md": "synthetic", "LICENSE": "synthetic", ".gitignore": ".env\n*.key\nid_*\n"} {
					if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if retained {
					if err := os.WriteFile(filepath.Join(root, "original.txt"), []byte("-----BEGIN PRIVATE KEY-----\nSYNTHETIC HEADER ONLY\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				args := []string{"-c", `ulimit -n 32 || exit 99; exec "$@"`, "sh", binaryPath, "audit", root, "--fail-on", "none"}
				if format == "quiet" {
					args = append(args, "--quiet")
				} else {
					args = append(args, "--output", format)
				}
				cmd := exec.CommandContext(ctx, "/bin/sh", args...)
				cmd.WaitDelay = time.Second
				cmd.Env = append(os.Environ(), "PATH="+t.TempDir(), "NO_COLOR=1")
				var out, diag bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diag
				err := cmd.Run()
				var exit *exec.ExitError
				if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 2 {
					t.Fatalf("observer failure exit: %v watchdog=%v stdout=%s stderr=%s", err, ctx.Err(), &out, &diag)
				}
				if format == "json" {
					r := integratedJSON(t, out.Bytes())
					if r.Status != scanstate.StatusPartial || r.Coverage.Traversal.InventoryComplete == nil || !*r.Coverage.Traversal.InventoryComplete {
						t.Fatalf("native inventory lost or failure hidden: %+v", r)
					}
					found, reason, gitPartial := false, false, false
					for _, f := range r.Findings {
						found = found || f.RuleID == "SEC-001" && f.Path == "original.txt"
					}
					for _, reasonEntry := range r.Coverage.Reasons {
						reason = reason || reasonEntry.Code == scanstate.ReasonGitFailure && reasonEntry.Count > 0
					}
					for _, c := range r.Coverage.Checks {
						gitPartial = gitPartial || c.RuleID == "GIT-002" && c.Status == scanstate.CheckStatusPartial
					}
					if found != retained || !retained && len(r.Findings) != 0 || !reason || !gitPartial {
						t.Fatalf("observer coverage/native findings: %+v", r)
					}
				} else {
					stream := out.String()
					if format == "quiet" {
						stream = diag.String()
						if !retained && out.Len() != 0 {
							t.Fatalf("zero finding quiet output: %s", &out)
						}
					}
					if !strings.Contains(stream, "PARTIAL") || !strings.Contains(strings.ToUpper(stream), "COVERAGE") || retained && !strings.Contains(out.String(), "original.txt") {
						t.Fatalf("observer failure/native finding hidden: stdout=%s stderr=%s", &out, &diag)
					}
				}
			})
		}
	}
}
