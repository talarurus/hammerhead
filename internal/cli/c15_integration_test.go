package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"

	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
	"golang.org/x/sys/unix"
)

type integratedReport struct {
	Schema     string           `json:"schema"`
	Version    string           `json:"version"`
	Status     scanstate.Status `json:"status"`
	Repository struct {
		Root string `json:"root"`
	} `json:"repository"`
	Threshold struct {
		FailOn   string `json:"fail_on"`
		Exceeded bool   `json:"exceeded"`
	} `json:"threshold"`
	Findings    []finding.Finding      `json:"findings"`
	Coverage    scanstate.Coverage     `json:"coverage"`
	Diagnostics []scanstate.Diagnostic `json:"diagnostics"`
}

func integratedJSON(t *testing.T, out []byte) integratedReport {
	t.Helper()
	var r integratedReport
	d := json.NewDecoder(bytes.NewReader(out))
	if err := d.Decode(&r); err != nil {
		t.Fatalf("not a JSON document: %v %q", err, out)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF || r.Schema != "hammerhead/v0.2" {
		t.Fatalf("mixed JSON output: %v %+v", err, r)
	}
	return r
}

func integratedRun(t *testing.T, limit time.Duration, path string, args ...string) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), "PATH="+path, "NO_COLOR=1")
	var out, diag bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diag
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("parent watchdog fired after %v: %v", limit, err)
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return out.Bytes(), diag.Bytes(), code
}

func TestCLI_SpecialFileNoHang(t *testing.T) {
	// Short, owned path also respects sockaddr_un limits on macOS.
	root, err := os.MkdirTemp("", "hh-special-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	socket, err := net.Listen("unix", filepath.Join(root, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	for name, data := range map[string]string{"README.md": "synthetic", "LICENSE": "synthetic", ".gitignore": ".env\n*.key\nid_*\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out, diag, code := integratedRun(t, 3*time.Second, t.TempDir(), "audit", root, "--output", "json", "--fail-on", "none")
	if code != 0 || len(diag) != 0 {
		t.Fatalf("special-file scan failed: code=%d stderr=%q", code, diag)
	}
	r := integratedJSON(t, out)
	if r.Status != scanstate.StatusCompleted || len(r.Findings) != 0 {
		t.Fatalf("expected safety skips without findings: %+v", r)
	}
	for _, c := range r.Coverage.Checks {
		if c.RuleID == "SEC-001" && (c.EligibleFiles == nil || *c.EligibleFiles != 3 || c.ReadBytes == nil || *c.ReadBytes <= 0) {
			t.Fatalf("special entries entered content inventory: %+v", c)
		}
	}
	// Direct guarded reads execute in a watched child too; no FIFO writer and
	// an actively listening socket must both produce zero content bytes.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "--g12-special-reader", root)
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil || ctx.Err() != nil {
		t.Fatalf("guarded special-file subprocess failed: %v %v %s", err, ctx.Err(), out)
	}
}

func runC15SpecialReader(root string) int {
	r, err := fs.NewGuardedReader(fs.ReaderConfig{RootPath: root})
	if err != nil {
		return 81
	}
	defer r.Close()
	for _, name := range []string{"pipe", "sock"} {
		out := r.ReadFile(context.Background(), name, fs.ReadOptions{MaxSize: 100})
		if out.Status != fs.ReadStatusSafetyReject || out.BytesRead != 0 || len(out.Data) != 0 {
			return 82
		}
	}
	return 0
}

func TestCLI_ActualTerminalInjection(t *testing.T) {
	parent := t.TempDir()
	name := "root\x1b[31m\x1b]52;c;OSC_PAYLOAD\a\r\nspoof\u202e"
	root := filepath.Join(parent, name)
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	accepted := "evil\u202e\u2066.key"
	rejected := "bad\x1b[2J\x1b]8;;OSC_PAYLOAD\x1b\\\r\nspoof.key"
	for _, name := range []string{accepted, rejected, "id_rsa"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic filename fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"terminal", "quiet", "json"} {
		args := []string{"audit", root, "--fail-on", "none"}
		if format == "quiet" {
			args = append(args, "--quiet")
		} else {
			args = append(args, "--output", format)
		}
		out, diag, code := integratedRun(t, 3*time.Second, t.TempDir(), args...)
		if code != 0 {
			t.Fatalf("%s failed: %d %q", format, code, diag)
		}
		if format == "json" {
			r := integratedJSON(t, out)
			if r.Repository.Root != root || len(diag) != 0 {
				t.Fatal("JSON root changed or streams mixed")
			}
			found := false
			for _, f := range r.Findings {
				found = found || f.Path == accepted
				if f.Path == rejected {
					t.Fatal("walker rejection changed")
				}
			}
			if !found {
				t.Fatal("accepted Unicode path lost")
			}
			continue
		}
		if !bytes.Contains(out, []byte("evil.key")) || !bytes.Contains(out, []byte("id_rsa")) {
			t.Fatal("supported findings lost during sanitization")
		}
		for _, stream := range [][]byte{out, diag} {
			for _, r := range string(stream) {
				if unicode.IsControl(r) && r != '\n' || unicode.Is(unicode.Cf, r) {
					t.Fatalf("terminal control U+%04X survived", r)
				}
			}
			if bytes.Contains(stream, []byte("OSC_PAYLOAD")) || bytes.Contains(stream, []byte("\nspoof")) {
				t.Fatalf("terminal spoof survived: %q", stream)
			}
		}
	}
}

// Trusted synthetic Git executable: the real CLI and production runner invoke
// this test binary outside the target. No shell, credentials or live Git hook.
func runC15GitHelper() {
	data, err := os.ReadFile(".g12-mode")
	if err != nil {
		os.Exit(89)
	}
	lock, err := os.Create(".g12-lock")
	if err != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		os.Exit(86)
	}
	defer lock.Close()
	if err := os.WriteFile(".g12-pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(88)
	}
	if string(data) == "failure" {
		os.Stderr.WriteString("SYNTHETIC_RAW_GIT_STDERR\x1b]52;c;PAYLOAD\a\n")
		os.Exit(1)
	}
	time.AfterFunc(15*time.Second, func() { os.Exit(87) })
	select {} // Production per-command timeout must terminate this owned helper.
}

func TestCLI_GitTimeoutRetainsNativeFindings(t *testing.T) {
	for _, mode := range []string{"timeout", "failure"} {
		t.Run(mode, func(t *testing.T) {
			root := g11EmptyRepo(t)
			for name, data := range map[string]string{"id_rsa": "synthetic filename fixture", ".g12-mode": mode} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			bin := t.TempDir()
			t.Cleanup(func() {
				lock, err := os.Open(filepath.Join(root, ".g12-lock"))
				if err != nil {
					return
				}
				defer lock.Close()
				if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
					syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
					return
				}
				data, _ := os.ReadFile(filepath.Join(root, ".g12-pid"))
				pid, _ := strconv.Atoi(string(data))
				if group, err := syscall.Getpgid(pid); err == nil && pid > 0 && group == pid && group != syscall.Getpgrp() {
					syscall.Kill(-group, syscall.SIGKILL)
				}
			})
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(exe, filepath.Join(bin, "git")); err != nil {
				t.Fatal(err)
			}
			out, diag, code := integratedRun(t, 15*time.Second, bin, "audit", root, "--output", "json", "--fail-on", "none")
			if code != 2 || bytes.Contains(diag, []byte("SYNTHETIC_RAW")) || bytes.Contains(out, []byte("SYNTHETIC_RAW")) {
				t.Fatalf("unsafe Git failure: code=%d stderr=%q", code, diag)
			}
			r := integratedJSON(t, out)
			if r.Status != scanstate.StatusPartial || r.Threshold.FailOn != "none" || r.Threshold.Exceeded {
				t.Fatalf("Git failure misclassified: %+v", r)
			}
			found := false
			for _, f := range r.Findings {
				found = found || f.RuleID == "FILE-001" && f.Path == "id_rsa"
			}
			want := scanstate.ReasonGitTimeout
			if mode == "failure" {
				want = scanstate.ReasonGitFailure
			}
			reason := false
			for _, d := range r.Diagnostics {
				reason = reason || d.Code == want
			}
			if !found || !reason {
				t.Fatalf("native finding or typed Git reason lost: %+v", r)
			}
			pidData, err := os.ReadFile(filepath.Join(root, ".g12-pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
			if err != nil || pid <= 0 {
				t.Fatal("invalid helper PID")
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				// Cleanup verifies the live fixture lock/group before signalling.
				t.Fatalf("owned Git helper still exists after CLI return: %v", err)
			}
		})
	}
}

func TestCLI_DevelopmentVersion(t *testing.T) {
	out, _, code := integratedRun(t, 3*time.Second, t.TempDir(), "version")
	if code != 0 || !bytes.Contains(out, []byte("0.2.0-dev")) {
		t.Fatalf("development version: code=%d %s", code, out)
	}
}
