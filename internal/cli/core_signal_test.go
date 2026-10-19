//go:build darwin || linux

package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/scanstate"
	"golang.org/x/sys/unix"
)

func TestCore_CommandSignalCancellation(t *testing.T) {
	binary := a2r2CLI(t) // Scheduling/read and cancellation-observation overlays only.
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			root := g11EmptyRepo(t)
			coreWrite(t, root, "a.key", "synthetic filename fixture")
			base := t.TempDir()
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
			ready, release, cancelled := fifo("ready"), fifo("release"), fifo("cancelled")
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "audit", root, "--output", "json", "--fail-on", "none")
			cmd.WaitDelay = time.Second
			cmd.Env = append(os.Environ(), "PATH="+base, "NO_COLOR=1", "A2R2_POINT=read", "A2R2_COMPONENT=.gitignore", "A2R2_READY="+ready.Name(), "A2R2_RELEASE="+release.Name(), "A2R2_CANCELLED="+cancelled.Name())
			var out, diag bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diag
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			finished := false
			defer func() {
				cancel()
				if !finished {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("signal child cleanup timeout")
					}
				}
			}()
			waitToken := func(f *os.File, want string) {
				t.Helper()
				read := make(chan string, 1)
				go func() { line, _ := bufio.NewReader(f).ReadString('\n'); read <- line }()
				select {
				case line := <-read:
					if line != want {
						t.Fatalf("barrier=%q want=%q", line, want)
					}
				case err := <-done:
					finished = true
					t.Fatalf("command stopped before barrier: %v", err)
				case <-ctx.Done():
					t.Fatal("signal barrier timeout")
				}
			}
			waitToken(ready, "ready\n")
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			waitToken(cancelled, "cancelled\n") // The real main context has observed the OS signal.
			if _, err := release.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				finished = true
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 {
					t.Fatalf("cancelled main exit=%v stdout=%s stderr=%s", err, &out, &diag)
				}
			case <-ctx.Done():
				t.Fatal("cancelled main did not finish")
			}
			r := integratedJSON(t, out.Bytes())
			if r.Status != scanstate.StatusCancelled {
				t.Fatalf("signal status=%s", r.Status)
			}
			found := false
			for _, f := range r.Findings {
				found = found || f.RuleID == "FILE-001" && f.Path == "a.key"
			}
			if !found {
				t.Fatal("signal discarded earlier finding")
			}
		})
	}
}
