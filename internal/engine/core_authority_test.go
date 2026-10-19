//go:build darwin || linux

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Inventory and all six Core checks must retain the same native authority
// even when the selected pathname is replaced between traversal and reads.
func TestCore_RootAuthorityThroughAllChecks(t *testing.T) {
	for _, kind := range []string{"unchanged", "rename", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			outside := filepath.Join(base, "outside")
			for _, dir := range []string{root, outside} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(dir, name, data string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{root, outside} {
				write(dir, "README.md", "synthetic")
				write(dir, "LICENSE", "synthetic")
				write(dir, ".gitignore", ".env\n*.key\n")
			}
			write(root, "original.txt", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC ORIGINAL\n")
			write(outside, "foreign.txt", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC FOREIGN\n")
			write(outside, "original.txt", "benign replacement\n")
			e := New(DefaultRegistry())
			e.newReader = func(config fs.ReaderConfig) (fs.GuardedReader, error) {
				if kind != "unchanged" {
					if err := os.Rename(root, root+"-pinned"); err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "directory":
						if err := os.Rename(outside, root); err != nil {
							t.Fatal(err)
						}
					case "symlink":
						if err := os.Symlink(outside, root); err != nil {
							t.Fatal(err)
						}
					}
				}
				if config.Root == nil || config.RootPath != "" {
					t.Fatal("reader given pathname authority")
				}
				return fs.NewGuardedReader(config)
			}
			result, err := e.Scan(context.Background(), root, nil)
			if err != nil || result.Status != scanstate.StatusCompleted || result.ChecksRun != 6 {
				t.Fatalf("native authority lost: %v %+v", err, result)
			}
			if len(result.Findings) != 1 || result.Findings[0].RuleID != "SEC-001" || result.Findings[0].Path != "original.txt" {
				t.Fatalf("redirected to replacement root: %+v", result.Findings)
			}
			for _, c := range result.Coverage.Checks {
				if c.Status != scanstate.CheckStatusCompleted {
					t.Fatalf("Core work incomplete: %+v", c)
				}
			}
		})
	}
}
