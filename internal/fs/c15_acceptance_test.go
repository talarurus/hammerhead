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

func TestWalk_LimitsStopEnumeration(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%02d.txt", i)), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	batches := 0
	*fs.TestHookAfterReadDirBatch = func() { batches++ }
	defer func() { *fs.TestHookAfterReadDirBatch = nil }()
	w, err := fs.NewSafeWalker(root, &fs.WalkerConfig{MaxDirectoryWidth: 4, DirectoryReadBatch: 2})
	if err != nil {
		t.Fatal(err)
	}
	files, inv, err := w.Walk(context.Background())
	if !errors.Is(err, fs.ErrBudgetExhausted) || inv.InventoryComplete || inv.RootListComplete || inv.RetainedFiles != 0 || len(files) != 1 || !files[0].IsDir || files[0].Path != "." {
		t.Fatalf("wide directory must retain only its root, discarding all children: files=%+v inv=%+v err=%v", files, inv, err)
	}
	if batches != 3 {
		t.Fatalf("enumeration continued past cap plus one bounded batch: %d", batches)
	}
}
