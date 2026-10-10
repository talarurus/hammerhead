package fs_test

import (
	"context"
	"errors"

	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/talarurus/hammerhead/internal/fs"
)

func TestWalk_WideDirectoryBounded(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 15; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
	}

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		MaxDirectoryWidth: 10,
	})

	_, inv, err := walker.Walk(context.Background())
	if err == nil {
		t.Errorf("Expected budget exhausted error, got nil")
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false")
	}
	if inv.RootListComplete {
		t.Errorf("RootListComplete should be false")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryWidthExceeded]; count != 1 {
		t.Errorf("Expected 1 SkipCategoryWidthExceeded, got %d", count)
	}
}

func TestWalk_ExcludedEntriesCountTowardBudget(t *testing.T) {
	tmpDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, "excluded1"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "excluded2"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "excluded3"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("data"), 0644)

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		MaxExaminedEntries: 3,
		ExcludePatterns:    []string{"excluded1", "excluded2", "excluded3"},
	})

	_, inv, err := walker.Walk(context.Background())
	if err == nil {
		t.Errorf("Expected examined budget exhausted error, got nil")
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false")
	}
}

func TestWalk_CancelBetweenBatches(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 200; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
	}

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		DirectoryReadBatch: 10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	batchesObserved := 0
	*fs.TestHookAfterReadDirBatch = func() {
		batchesObserved++
		if batchesObserved == 1 {
			cancel()
		}
	}
	defer func() { *fs.TestHookAfterReadDirBatch = nil }()

	_, inv, err := walker.Walk(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context canceled error, got: %v", err)
	}
	if batchesObserved != 1 {
		t.Errorf("Expected exactly one batch to be observed, got: %d", batchesObserved)
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false")
	}

	if inv.RootListComplete {
		t.Errorf("RootListComplete should be false")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryCancelled]; count == 0 {
		t.Errorf("Expected SkipCategoryCancelled count > 0")
	}
}

func TestWalk_DepthMakesPartial(t *testing.T) {
	tmpDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, "dir1", "dir2", "dir3"), 0755)

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		MaxDepth: 2,
	})

	_, inv, err := walker.Walk(context.Background())
	if err == nil {
		t.Errorf("Expected depth budget exhausted error, got nil")
	}

	if inv.InventoryComplete {
		t.Errorf("InventoryComplete should be false")
	}
	if !inv.DepthExhausted {
		t.Errorf("DepthExhausted should be true")
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryDepthExceeded]; count != 1 {
		t.Errorf("Expected 1 SkipCategoryDepthExceeded, got %d", count)
	}
}

func TestWalk_StableSiblingOrder(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "b.txt"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "c.txt"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("data"), 0644)

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	files, _, err := walker.Walk(context.Background())
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	var names []string
	for _, f := range files {
		if !f.IsDir {
			names = append(names, filepath.Base(f.Path))
		}
	}

	if len(names) != 3 || names[0] != "a.txt" || names[1] != "b.txt" || names[2] != "c.txt" {
		t.Errorf("Expected stable order [a.txt, b.txt, c.txt], got %v", names)
	}
}

func TestWalk_RootEnumerationIncomplete(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 15; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
	}

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		MaxDirectoryWidth: 10,
	})

	_, inv, err := walker.Walk(context.Background())
	if err == nil {
		t.Errorf("Expected width budget error")
	}

	if inv.RootListComplete {
		t.Errorf("RootListComplete should be false due to incomplete root enumeration")
	}
}

func TestWalk_GitfileExcluded(t *testing.T) {
	tmpDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, ".git"), 0755)
	os.WriteFile(filepath.Join(tmpDir, ".git", "config"), []byte("data"), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "sub"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "sub", ".git"), []byte("gitdir: /tmp/foo"), 0644)

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	files, _, err := walker.Walk(context.Background())
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	for _, f := range files {
		if filepath.Base(f.Path) == ".git" {
			t.Errorf(".git should be excluded (found at %s)", f.Path)
		}

		if f.Path == ".git" {
			t.Errorf(".git should be excluded")
		}
	}

	if count := walker.SkippedCounts()[fs.SkipCategoryGitfile]; count != 2 {
		t.Errorf("Expected 1 SkipCategoryGitfile, got %d", count)
	}
}

func TestInventory_ExcludedRootCandidateUnknown(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("data"), 0644)

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{
		ExcludePatterns: []string{"README.md"},
	})

	_, inv, err := walker.Walk(context.Background())
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	if inv.RootREADME != fs.PresenceUnknown {
		t.Errorf("Expected RootREADME to be PresenceUnknown when excluded, got %v", inv.RootREADME)
	}
}

func TestInventory_BrokenRootSymlink(t *testing.T) {
	tmpDir := t.TempDir()

	os.Symlink("broken_target", filepath.Join(tmpDir, "README.md"))
	os.Symlink("broken_target2", filepath.Join(tmpDir, "LICENSE"))
	os.Symlink("broken_target3", filepath.Join(tmpDir, ".gitignore"))

	walker, _ := fs.NewSafeWalker(tmpDir, &fs.WalkerConfig{})
	_, inv, _ := walker.Walk(context.Background())

	if inv.RootREADME != fs.PresenceUnknown {
		t.Errorf("Expected RootREADME to be PresenceUnknown for broken symlink, got %v", inv.RootREADME)
	}
	if inv.RootLICENSE != fs.PresenceUnknown {
		t.Errorf("Expected RootLICENSE to be PresenceUnknown for broken symlink, got %v", inv.RootLICENSE)
	}
	if inv.RootGitignore != fs.PresenceUnknown {
		t.Errorf("Expected RootGitignore to be PresenceUnknown for broken symlink, got %v", inv.RootGitignore)
	}
}
