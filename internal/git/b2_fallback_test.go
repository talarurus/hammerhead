//go:build darwin || linux

package git

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real Fatal path in a separate test process: testing must remove
// the binary's TempDir even when b2CandidateBinary never returns to its caller.
func TestB2_FallbackLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "failure"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			tmp := filepath.Join(root, "tmp")
			if err := os.Mkdir(tmp, 0700); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestB2_FallbackLifecycleChild$", "-test.v")
			cmd.Env = append(os.Environ(), "HAMMERHEAD_B2_CANDIDATE=", "HAMMERHEAD_B2_FALLBACK_CASE="+mode, "TMPDIR="+tmp)
			out, err := cmd.CombinedOutput()
			want := 0
			if mode == "failure" {
				want = 1
			}
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("fallback child: %v output=%s", err, out)
				}
				code = exit.ExitCode()
			}
			entries, readErr := os.ReadDir(tmp)
			if ctx.Err() != nil || code != want || readErr != nil || len(entries) != 0 || (mode == "failure" && !strings.Contains(string(out), "B2 candidate build:")) {
				t.Fatalf("fallback %s exit=%d want=%d leftovers=%v error=%v timeout=%v output=%s", mode, code, want, entries, readErr, ctx.Err(), out)
			}
			if evidence := os.Getenv("HAMMERHEAD_B2_EVIDENCE"); evidence != "" {
				data, _ := json.MarshalIndent(map[string]any{"mode": mode, "exit": code, "temporary_entries_after_exit": len(entries), "timeout": ctx.Err() != nil, "output": string(out)}, "", "  ")
				if err := os.WriteFile(filepath.Join(evidence, "fallback-"+mode+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("fallback %s: child exit=%d; temporary directory empty", mode, code)
		})
	}
}

func TestB2_FallbackLifecycleChild(t *testing.T) {
	mode := os.Getenv("HAMMERHEAD_B2_FALLBACK_CASE")
	if mode == "" {
		return // Only the isolated lifecycle controller runs this child.
	}
	if mode == "failure" {
		// The fixed relative source path is absent below an owned fresh root.
		// Use the real Go compiler; do not replace PATH with an executable mock.
		t.Chdir(t.TempDir())
	} else if mode != "success" {
		t.Fatal("unknown fallback lifecycle case")
	}
	path := b2CandidateBinary(t)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("fallback binary missing", err)
	}
	if mode == "failure" {
		t.Fatal("expected fallback build to fail")
	}
}
