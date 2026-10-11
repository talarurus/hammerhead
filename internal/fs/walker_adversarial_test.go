//go:build unix || darwin || linux
// +build unix darwin linux

package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/fs"
	"golang.org/x/sys/unix"
)

func TestWalk_Adversarial_AncestorSwapOutsideRoot(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, "A", "B"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "A", "B", "file.txt"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "A", "B", "secret.txt"), []byte("secret"), 0644)

	swapped := false
	*fs.TestHookBeforeOpenDir = func(childName string) {
		if childName == "B" && !swapped {
			os.Rename(filepath.Join(tmpDir, "A"), filepath.Join(outsideDir, "A_moved"))
			os.Symlink(filepath.Join(outsideDir, "A_moved"), filepath.Join(tmpDir, "A"))
			swapped = true
		}
	}
	defer func() { *fs.TestHookBeforeOpenDir = nil }()

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	files, inv, err := walker.Walk(context.Background())

	for _, f := range files {
		if strings.Contains(f.Path, "secret.txt") {
			t.Errorf("Walked outside sentinel: %s", f.Path)
		}
	}

	if err != nil {
		t.Errorf("Expected walk to succeed and skip tampered directory, got error: %v", err)
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false on tampered chain")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryWalkError]; count == 0 {
		t.Errorf("Expected SkipCategoryWalkError due to tampered chain, got 0")
	}
}

func TestWalk_Adversarial_ChildDirectoryReplacedWithInode(t *testing.T) {
	tmpDir := t.TempDir()
	childPath := filepath.Join(tmpDir, "A")

	if err := os.Mkdir(childPath, 0755); err != nil {
		t.Fatal(err)
	}
	// Keep the original inode allocated after unlinking it. Without this handle,
	// the filesystem may reuse its device/inode pair for the replacement, so the
	// fixture would not actually exercise the changed-identity check.
	original, err := os.Open(childPath)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	var originalIdentity unix.Stat_t
	if err := unix.Fstat(int(original.Fd()), &originalIdentity); err != nil {
		t.Fatal(err)
	}

	swapped := false
	*fs.TestHookBeforeOpenDir = func(childName string) {
		if childName == "A" && !swapped {
			if err := os.RemoveAll(childPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(childPath, 0755); err != nil {
				t.Fatal(err)
			}
			var replacementIdentity unix.Stat_t
			if err := unix.Lstat(childPath, &replacementIdentity); err != nil {
				t.Fatal(err)
			}
			if originalIdentity.Dev == replacementIdentity.Dev && originalIdentity.Ino == replacementIdentity.Ino {
				t.Fatalf("fixture did not replace directory identity: dev=%d ino=%d", originalIdentity.Dev, originalIdentity.Ino)
			}
			t.Logf("directory replacement: original dev=%d ino=%d; replacement dev=%d ino=%d",
				originalIdentity.Dev, originalIdentity.Ino, replacementIdentity.Dev, replacementIdentity.Ino)
			if err := os.WriteFile(filepath.Join(childPath, "secret.txt"), []byte("data"), 0644); err != nil {
				t.Fatal(err)
			}
			swapped = true
		}
	}
	defer func() { *fs.TestHookBeforeOpenDir = nil }()

	walker, err := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	files, inv, err := walker.Walk(context.Background())
	if !swapped {
		t.Fatal("directory replacement hook did not run")
	}

	for _, f := range files {
		if strings.Contains(f.Path, "secret.txt") {
			t.Errorf("Walked child with new inode: %s", f.Path)
		}
	}

	if err != nil {
		t.Errorf("Expected walk to succeed and skip tampered directory, got error: %v", err)
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false on changed directory identity")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryWalkError]; count == 0 {
		t.Errorf("Expected SkipCategoryWalkError due to changed identity, got 0")
	}
}

func TestWalk_Adversarial_ChildDirectoryReplacedWithFIFO(t *testing.T) {
	tmpDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, "A"), 0755)

	swapped := false
	*fs.TestHookBeforeOpenDir = func(childName string) {
		if childName == "A" && !swapped {
			os.RemoveAll(filepath.Join(tmpDir, "A"))
			// Create a FIFO
			unix.Mkfifo(filepath.Join(tmpDir, "A"), 0644)
			swapped = true
		}
	}
	defer func() { *fs.TestHookBeforeOpenDir = nil }()

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	_, inv, err := walker.Walk(context.Background())

	if err != nil {
		t.Errorf("Expected walk to succeed and skip tampered directory, got error: %v", err)
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false on changed directory identity (FIFO)")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryWalkError]; count == 0 {
		t.Errorf("Expected SkipCategoryWalkError due to FIFO substitution, got 0")
	}
}
