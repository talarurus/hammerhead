//go:build darwin || linux

package fs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestA2R2_RequiredReadFailures(t *testing.T) {
	if readerWatchdog(t, "TestA2R2_RequiredReadFailures") {
		return
	}
	for _, kind := range []string{"file", "ancestor-post", "ancestor-pre", "ancestor-missing", "content"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			if err := os.MkdirAll(filepath.Join(root, "dir"), 0700); err != nil {
				t.Fatal(err)
			}
			write := func(path, data string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "plain.txt"), "ordinary text\n")
			path := filepath.Join(root, "dir", "probe.txt")
			write(path, "ordinary text\n")
			if kind == "ancestor-pre" || kind == "ancestor-missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "dir", "sub"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("sub/../../plain.txt", path); err != nil {
					t.Fatal(err)
				}
			}
			mutated := false
			mutate := func() {
				t.Helper()
				if mutated {
					t.Fatal("mutation hook repeated")
				}
				mutated = true
				switch kind {
				case "file":
					if err := os.Rename(path, filepath.Join(base, "original-file")); err != nil {
						t.Fatal(err)
					}
					write(path, "REJECTED SYNTHETIC CONTENT\n")
				case "content":
					write(path, "MUTATED SYNTHETIC CONTENT\n")
				default:
					if err := os.Rename(filepath.Join(root, "dir"), filepath.Join(base, "original-dir")); err != nil {
						t.Fatal(err)
					}
					if kind != "ancestor-missing" {
						if err := os.Mkdir(filepath.Join(root, "dir"), 0700); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			hooks := &readerHooks{}
			switch kind {
			case "file", "ancestor-post":
				hooks.beforeOpenat = func(comp string) {
					if comp == "probe.txt" {
						mutate()
					}
				}
			case "ancestor-pre", "ancestor-missing":
				hooks.beforeReadlinkat = func(comp string) {
					if comp == "probe.txt" {
						mutate()
					}
				}
			case "content":
				hooks.beforeRead = mutate
			}
			aggregate := int64(0)
			r, err := newGuardedReaderWithHooks(ReaderConfig{RootPath: root, AggregateReadBytes: &aggregate, MaxAggregate: 1024}, hooks)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			out := r.ReadFile(context.Background(), "dir/probe.txt", ReadOptions{MaxSize: 1024})
			if !mutated || out.Status != ReadStatusError || out.Err == nil || len(out.Data) != 0 {
				t.Fatalf("required read failure became a skip or exposed content: %+v", out)
			}
			if kind != "content" && (out.BytesRead != 0 || aggregate != 0) {
				t.Fatalf("rejected metadata caused content access: outcome=%+v aggregate=%d", out, aggregate)
			}
		})
	}
}

func TestA2R2_ReadPolicySkips(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{"plain.txt": "text\n", "binary.txt": "\x00\x01", "large.txt": strings.Repeat("x", 101), "excluded.txt": "excluded\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"relative": "plain.txt", "excluded-alias": "excluded.txt", "escape": "../outside", "loop": "loop"} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewGuardedReader(ReaderConfig{RootPath: root, IsExcluded: func(path, base string) bool { return base == "excluded.txt" }})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for name, want := range map[string]ReadStatus{"plain.txt": ReadStatusText, "relative": ReadStatusText, "binary.txt": ReadStatusBinary, "large.txt": ReadStatusTooLarge, "excluded.txt": ReadStatusSafetyReject, "excluded-alias": ReadStatusSafetyReject, "escape": ReadStatusSafetyReject, "loop": ReadStatusSafetyReject} {
		t.Run(name, func(t *testing.T) {
			out := r.ReadFile(context.Background(), name, ReadOptions{MaxSize: 100})
			if out.Status != want {
				t.Fatalf("policy outcome=%+v want=%s", out, want)
			}
		})
	}
}
