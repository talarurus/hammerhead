package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode"
)

// No Git subprocess can start in these cases: PATH names an empty owned directory.
// CommandContext is the parent watchdog, WaitDelay bounds pipe cleanup, and every
// inherited pipe endpoint is closed by the parent immediately after Start.
func g11Command(t *testing.T, args ...string) (*exec.Cmd, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.WaitDelay = time.Second
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "PATH=") && !strings.HasPrefix(item, "NO_COLOR=") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+t.TempDir(), "NO_COLOR=1")
	return cmd, ctx
}

func g11ClosedPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func TestCLI_BrokenPipeExit2(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix SIGPIPE policy is validated on macOS and Linux")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "id_rsa"), []byte("synthetic filename-only fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	clean := g11EmptyRepo(t)
	partial := g11EmptyRepo(t)
	current := partial
	for i := 0; i < 52; i++ {
		current = filepath.Join(current, "d")
		if err := os.Mkdir(current, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name           string
		args           []string
		stdout, stderr bool
	}{
		{"version-stdout", []string{"version"}, true, false},
		{"help-stdout", []string{"--help"}, true, false},
		{"audit-help-stdout", []string{"help", "audit"}, true, false},
		{"terminal-stdout", []string{"audit", root}, true, false},
		{"json-stdout", []string{"audit", root, "--output", "json"}, true, false},
		{"quiet-stdout", []string{"audit", root, "--quiet"}, true, false},
		{"quiet-stderr", []string{"audit", root, "--quiet"}, false, true},
		{"error-stderr", []string{"unknown-command"}, false, true},
		{"quiet-zero-completed-stderr", []string{"audit", clean, "--quiet"}, false, true},
		{"quiet-zero-partial-stderr", []string{"audit", partial, "--quiet", "--fail-on", "none"}, false, true},
		{"both-pipes", []string{"audit", root, "--output", "json"}, true, true},
		{"version-both-pipes", []string{"version"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, ctx := g11Command(t, tc.args...)
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			var pipes []*os.File
			if tc.stdout {
				p := g11ClosedPipe(t)
				cmd.Stdout = p
				pipes = append(pipes, p)
			}
			if tc.stderr {
				p := g11ClosedPipe(t)
				cmd.Stderr = p
				pipes = append(pipes, p)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for _, p := range pipes {
				p.Close()
			}
			err := cmd.Wait()
			if ctx.Err() != nil {
				t.Fatalf("parent watchdog fired: %v", ctx.Err())
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("broken pipe must exit 2, not a signal: %v; stdout=%q stderr=%q", err, out.String(), diag.String())
			}
			if tc.stdout && !tc.stderr && !strings.Contains(diag.String(), "writing output failed") {
				t.Fatalf("missing best-effort stderr: %q", diag.String())
			}
		})
	}
}

func TestCLI_MaliciousFilenameStreams(t *testing.T) {
	root := t.TempDir()
	// The existing walker rejects control-bearing names. A bidi-only name is
	// accepted by that boundary and must be sanitized by the renderer itself.
	name := "evil\u202e\u2066.key"
	rejected := "evil\x1b[31m\x1b]52;c;OSC_PAYLOAD\a\r\nspoof.key"
	if err := os.WriteFile(filepath.Join(root, rejected), []byte("synthetic rejected filename"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic filename-only fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"terminal", "quiet", "json"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"audit", root, "--fail-on", "none"}
			if format == "quiet" {
				args = append(args, "--quiet")
			} else {
				args = append(args, "--output", format)
			}
			cmd, ctx := g11Command(t, args...)
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			if err := cmd.Run(); err != nil || ctx.Err() != nil {
				t.Fatalf("invocation failed: %v %v stderr=%s", err, ctx.Err(), diag.String())
			}
			if format == "json" {
				var report struct {
					Findings []struct {
						Path string `json:"path"`
					} `json:"findings"`
				}
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, f := range report.Findings {
					if f.Path == rejected {
						t.Fatal("walker rejection/path matching changed")
					}
					found = found || f.Path == name
				}
				if !found || diag.Len() != 0 {
					t.Fatalf("original JSON path lost or stdout/stderr mixed: %+v %q", report, diag.String())
				}
				return
			}
			if !strings.Contains(out.String(), "evil.key") {
				t.Fatalf("accepted malicious filename was not rendered: %q", out.String())
			}
			for _, stream := range []string{out.String(), diag.String()} {
				for _, r := range stream {
					if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) {
						t.Fatalf("malicious terminal control survived: %q", stream)
					}
				}
				if strings.Contains(stream, "OSC_PAYLOAD") || strings.Contains(stream, "\nspoof") {
					t.Fatalf("OSC payload/header spoof survived: %q", stream)
				}
			}
		})
	}
}

func g11EmptyRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{"README.md": "synthetic fixture", "LICENSE": "synthetic fixture", ".gitignore": ".env\n*.key\nid_*\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCLI_QuietZeroFindingsPartialEndToEnd(t *testing.T) {
	root := g11EmptyRepo(t)
	current := root
	for i := 0; i < 52; i++ {
		current = filepath.Join(current, "d")
		if err := os.Mkdir(current, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"json", "quiet"} {
		args := []string{"audit", root, "--fail-on", "none"}
		if format == "json" {
			args = append(args, "--output", "json")
		} else {
			args = append(args, "--quiet")
		}
		cmd, ctx := g11Command(t, args...)
		var out, diag bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diag
		err := cmd.Run()
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Fatalf("fixture did not exit 2: %v %v", err, ctx.Err())
		}
		if format == "json" {
			var report struct {
				Status   string `json:"status"`
				Findings []any  `json:"findings"`
			}
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != "partial" || len(report.Findings) != 0 {
				t.Fatalf("fixture should be partial with zero findings: %+v", report)
			}
		} else if out.Len() != 0 || !strings.Contains(diag.String(), "[STATUS] PARTIAL") || !strings.Contains(diag.String(), "[COVERAGE]") {
			t.Fatalf("quiet incomplete zero findings hidden/misrouted: stdout=%q stderr=%q", out.String(), diag.String())
		}
	}
}
