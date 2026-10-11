//go:build darwin || linux

package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// Build the actual CLI with only a scheduling hook installed in the existing
// readerHooks seam. The overlay is temporary; production has no environment
// switch or global hook. All resolver, check, engine and reporting code is real.
func a2r2CLI(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "internal/fs/reader_unix.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor := "\t\trootFile: f,\n"
	if strings.Count(string(source), anchor) != 1 {
		t.Fatal("reader constructor hook anchor changed")
	}
	instrumented := strings.Replace(string(source), anchor, anchor+"\t\thooks: a2r2SchedulingHooks(),\n", 1)
	instrumented += `
// Test overlay only: block once at the selected native-read boundary.
func a2r2SchedulingHooks() *readerHooks {
	done := false
	leaf := ""
	barrier := func(point, comp string) {
		if done || point != os.Getenv("A2R2_POINT") || comp != os.Getenv("A2R2_COMPONENT") { return }
		done = true
		if err := os.WriteFile(os.Getenv("A2R2_READY"), []byte("ready\n"), 0600); err != nil { panic(err) }
		f, err := os.Open(os.Getenv("A2R2_RELEASE")); if err != nil { panic(err) }
		var token [1]byte
		_, err = io.ReadFull(f, token[:]); f.Close(); if err != nil { panic(err) }
	}
	return &readerHooks{
		beforeOpenat: func(comp string) { leaf = comp; barrier("open", comp) },
		beforeReadlinkat: func(comp string) { barrier("readlink", comp) },
		beforeRead: func() { barrier("read", leaf) },
	}
}
`
	tmp := t.TempDir()
	replacement := filepath.Join(tmp, "reader_unix.go")
	if err := os.WriteFile(replacement, []byte(instrumented), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{path: replacement}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(tmp, "hammerhead")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-overlay", overlayPath, "-o", binary, "./cmd/hammerhead")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("instrumented CLI build: %v: %s", err, out)
	}
	return binary
}

func TestA2R2_EligibleMutationCLI(t *testing.T) {
	binary := a2r2CLI(t)
	for _, kind := range []string{"file", "ancestor-post", "ancestor-pre", "ancestor-missing", "content", "unchanged", "relative", "late-excluded", "excluded", "binary", "oversize"} {
		for _, format := range []string{"json", "terminal", "quiet"} {
			for _, threshold := range []string{"none", "high"} {
				for _, retained := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/retained=%t", kind, format, threshold, retained), func(t *testing.T) {
						base := t.TempDir()
						root := filepath.Join(base, "root")
						if err := os.Mkdir(root, 0700); err != nil {
							t.Fatal(err)
						}
						write := func(path, data string) {
							t.Helper()
							if err := os.WriteFile(path, []byte(data), 0600); err != nil {
								t.Fatal(err)
							}
						}
						for name, data := range map[string]string{"README.md": "synthetic", "LICENSE": "synthetic", ".gitignore": ".env\n*.key\nid_*\n", "z-probe.txt": "ordinary text\n", "excluded.txt": "-----BEGIN PRIVATE KEY-----\nEXCLUDED SYNTHETIC\n"} {
							write(filepath.Join(root, name), data)
						}
						if retained {
							write(filepath.Join(root, "a-earlier.txt"), "-----BEGIN PRIVATE KEY-----\nEARLIER SYNTHETIC\n")
						}
						probe := filepath.Join(root, "z-probe.txt")
						point, component := "", ""
						changed := false
						switch kind {
						case "file", "content":
							changed = true
							point, component = "open", "z-probe.txt"
							if kind == "content" {
								point = "read"
							}
						case "ancestor-post", "ancestor-pre", "ancestor-missing":
							changed = true
							if err := os.Remove(probe); err != nil {
								t.Fatal(err)
							}
							if err := os.Mkdir(filepath.Join(root, "z-dir"), 0700); err != nil {
								t.Fatal(err)
							}
							probe = filepath.Join(root, "z-dir", "z-probe.txt")
							point, component = "open", "z-probe.txt"
							if kind == "ancestor-post" {
								write(probe, "ordinary text\n")
							} else {
								write(filepath.Join(root, "plain.txt"), "ordinary text\n")
								if err := os.Mkdir(filepath.Join(root, "z-dir", "sub"), 0700); err != nil {
									t.Fatal(err)
								}
								if err := os.Symlink("sub/../../plain.txt", probe); err != nil {
									t.Fatal(err)
								}
								point = "readlink"
							}
						case "relative", "late-excluded":
							if err := os.Remove(probe); err != nil {
								t.Fatal(err)
							}
							write(filepath.Join(root, "plain.txt"), "ordinary text\n")
							if err := os.Symlink("plain.txt", probe); err != nil {
								t.Fatal(err)
							}
							if kind == "late-excluded" {
								point, component = "readlink", "z-probe.txt"
							}
						case "binary":
							write(probe, "\x00\x01\x02\x03")
						case "oversize":
							if err := os.Truncate(probe, 5*1024*1024+1); err != nil {
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
						ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
						defer cancel()
						args := []string{"audit", root, "--fail-on", threshold, "--exclude", "excluded.txt"}
						if kind == "excluded" {
							args = append(args, "--exclude", "z-probe.txt")
						}
						if format == "quiet" {
							args = append(args, "--quiet")
						} else {
							args = append(args, "--output", format)
						}
						cmd := exec.CommandContext(ctx, binary, args...)
						cmd.WaitDelay = time.Second
						cmd.Env = append(os.Environ(), "PATH="+base, "NO_COLOR=1", "A2R2_POINT="+point, "A2R2_COMPONENT="+component, "A2R2_READY="+ready.Name(), "A2R2_RELEASE="+release.Name())
						var out, diag bytes.Buffer
						cmd.Stdout, cmd.Stderr = &out, &diag
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						done := make(chan error, 1)
						go func() { done <- cmd.Wait() }()
						finished := false
						defer func() {
							// Unblock readiness readers even if the CLI fails before its hook.
							ready.Write([]byte("cleanup\n"))
							cancel()
							if !finished {
								select {
								case <-done:
								case <-time.After(3 * time.Second):
									t.Error("CLI watchdog cleanup failed")
								}
							}
						}()
						if point != "" {
							barrier := make(chan error, 1)
							go func() { _, err := bufio.NewReader(ready).ReadString('\n'); barrier <- err }()
							select {
							case err := <-barrier:
								if err != nil {
									t.Fatal(err)
								}
							case err := <-done:
								finished = true
								// Do not inspect buffers until Wait has joined the copy goroutines.
								t.Fatalf("CLI ended before reader barrier: %v stdout=%s stderr=%s", err, &out, &diag)
							case <-ctx.Done():
								t.Fatal("reader barrier watchdog fired")
							}
							switch kind {
							case "file":
								// Retain the original inode; no deletion/reuse ambiguity.
								if err := os.Rename(probe, filepath.Join(base, "original")); err != nil {
									t.Fatal(err)
								}
								write(probe, "-----BEGIN PRIVATE KEY-----\nREJECTED SYNTHETIC\n")
							case "ancestor-post", "ancestor-pre", "ancestor-missing":
								if err := os.Rename(filepath.Join(root, "z-dir"), filepath.Join(base, "original-dir")); err != nil {
									t.Fatal(err)
								}
								if kind != "ancestor-missing" {
									if err := os.Mkdir(filepath.Join(root, "z-dir"), 0700); err != nil {
										t.Fatal(err)
									}
								}
							case "content":
								write(probe, "-----BEGIN PRIVATE KEY-----\nMUTATED SYNTHETIC\n")
							case "late-excluded":
								if err := os.Remove(probe); err != nil {
									t.Fatal(err)
								}
								if err := os.Symlink("excluded.txt", probe); err != nil {
									t.Fatal(err)
								}
							}
							if _, err := release.Write([]byte("release\n")); err != nil {
								t.Fatal(err)
							}
						}
						var runErr error
						select {
						case runErr = <-done:
							finished = true
						case <-ctx.Done():
							t.Fatal("CLI watchdog fired")
						}
						code := 0
						if runErr != nil {
							var exit *exec.ExitError
							if !errors.As(runErr, &exit) {
								t.Fatal(runErr)
							}
							code = exit.ExitCode()
						}
						want := 0
						if changed {
							want = 2
						} else if retained && threshold == "high" {
							want = 1
						}
						if code != want {
							t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", code, want, &out, &diag)
						}
						if format == "json" {
							r := integratedJSON(t, out.Bytes())
							status := scanstate.StatusCompleted
							if changed {
								status = scanstate.StatusPartial
							}
							if r.Status != status || r.Coverage.Traversal.InventoryComplete == nil || !*r.Coverage.Traversal.InventoryComplete || r.Coverage.Traversal.RootListingComplete == nil || !*r.Coverage.Traversal.RootListingComplete {
								t.Fatalf("status/inventory lost: %+v", r)
							}
							earlier := 0
							if retained {
								earlier = 1
							}
							if len(r.Findings) != earlier || earlier == 1 && (r.Findings[0].RuleID != "SEC-001" || r.Findings[0].Path != "a-earlier.txt") {
								t.Fatalf("earlier finding lost or rejected/excluded content used: %+v", r.Findings)
							}
							secSeen := false
							for _, c := range r.Coverage.Checks {
								if c.RuleID != "SEC-001" {
									continue
								}
								secSeen = true
								wantStatus := scanstate.CheckStatusCompleted
								if changed {
									wantStatus = scanstate.CheckStatusPartial
								}
								if c.Status != wantStatus || c.EligibleFiles == nil || c.InspectedFiles == nil || *c.InspectedFiles >= *c.EligibleFiles && changed {
									t.Fatalf("Security completion/coverage incorrect: %+v", c)
								}
								a2r2Reason(t, c.ReasonCounts, changed)
							}
							if !secSeen {
								t.Fatal("Security check coverage absent")
							}
							a2r2Reason(t, r.Coverage.Reasons, changed)
						} else {
							if strings.Contains(out.String(), "z-probe.txt") || strings.Contains(out.String(), "REJECTED SYNTHETIC") || strings.Contains(out.String(), "MUTATED SYNTHETIC") || strings.Contains(out.String(), "EXCLUDED SYNTHETIC") {
								t.Fatalf("rejected/excluded content became a finding: %s", &out)
							}
							if retained != strings.Contains(out.String(), "a-earlier.txt") {
								t.Fatalf("earlier finding retention incorrect: %s", &out)
							}
							stream := out.String()
							if format == "quiet" {
								stream = diag.String()
								if !retained && out.Len() != 0 {
									t.Fatalf("quiet zero-findings stdout: %s", &out)
								}
							}
							if changed && (!strings.Contains(stream, "PARTIAL") || !strings.Contains(strings.ToUpper(stream), "COVERAGE") || !strings.Contains(stream, "eligible_read_failure")) {
								t.Fatalf("incomplete evaluation hidden: %s", stream)
							}
							if !changed && strings.Contains(stream, "PARTIAL") {
								t.Fatalf("policy skip became partial: %s", stream)
							}
						}
					})
				}
			}
		}
	}
}

func a2r2Reason(t *testing.T, reasons []scanstate.Reason, changed bool) {
	t.Helper()
	found := false
	for _, r := range reasons {
		if r.Code == scanstate.ReasonEligibleReadFailure {
			found = true
			if r.Count != 1 || r.CountIsLowerBound || len(r.Examples) != 1 || !strings.HasSuffix(r.Examples[0], "z-probe.txt") {
				t.Fatalf("mutation reason accounting incorrect: %+v", r)
			}
		}
	}
	if found != changed {
		t.Fatalf("mutation/policy reason classification: %+v", reasons)
	}
}
