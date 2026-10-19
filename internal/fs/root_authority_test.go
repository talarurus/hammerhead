//go:build darwin || linux

package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func assertClosedFD(t *testing.T, fd int) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != unix.EBADF {
		t.Fatalf("fd %d still live: %v", fd, err)
	}
}

func rootDescriptorCount(t *testing.T, root *RootHandle) int {
	t.Helper()
	var rootStat unix.Stat_t
	if err := unix.Fstat(int(root.file.Fd()), &rootStat); err != nil {
		t.Fatal(err)
	}
	path := "/dev/fd"
	if runtime.GOOS == "linux" {
		path = "/proc/self/fd"
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Dev == rootStat.Dev && st.Ino == rootStat.Ino {
			count++
		}
	}
	return count
}

func TestA2R1_RootAuthority(t *testing.T) {
	if readerWatchdog(t, "TestA2R1_RootAuthority") {
		return
	}
	for _, kind := range []string{"unchanged", "rename", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "root")
			outside := filepath.Join(base, "outside")
			for _, p := range []string{path, outside} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range []string{path, outside} {
				if err := os.WriteFile(filepath.Join(p, "file.txt"), []byte(filepath.Base(p)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("file.txt", filepath.Join(path, "relative")); err != nil {
				t.Fatal(err)
			}
			w, err := NewSafeWalker(path, &WalkerConfig{ExcludePatterns: []string{"blocked"}})
			if err != nil {
				t.Fatal(err)
			}
			root, err := w.OpenRoot()
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			ownerFD := int(root.file.Fd())
			files, inv, err := w.WalkRoot(context.Background(), root)
			if err != nil || !inv.InventoryComplete || len(files) != 3 {
				t.Fatalf("walk: %v %+v %+v", err, inv, files)
			}
			if kind != "unchanged" {
				if err := os.Rename(path, filepath.Join(base, "original")); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Symlink(outside, path); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "directory" {
					if err := os.Rename(outside, path); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Traversal also derives authority from the original object after
			// pathname replacement, using a fresh directory offset each time.
			files, inv, err = w.WalkRoot(context.Background(), root)
			if err != nil || !inv.InventoryComplete || len(files) != 3 {
				t.Fatalf("root-relative walk after %s: %v %+v %+v", kind, err, inv, files)
			}
			// An invalid pathname proves reader construction uses only the handle.
			reader, err := NewGuardedReader(ReaderConfig{Root: root, RootPath: "/does/not/exist", IsExcluded: w.IsExcluded})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			readerFD := int(reader.(*guardedReaderUnix).rootFile.Fd())
			if readerFD == ownerFD {
				t.Fatal("reader stole owner descriptor")
			}
			flags, err := unix.FcntlInt(uintptr(readerFD), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("CLOEXEC: %d %v", flags, err)
			}
			for _, name := range []string{"file.txt", "relative"} {
				got := reader.ReadFile(context.Background(), name, ReadOptions{MaxSize: 100})
				if got.Status != ReadStatusText || string(got.Data) != "root" {
					t.Fatalf("redirected read %s: %+v", name, got)
				}
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			assertClosedFD(t, ownerFD)
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewGuardedReader(ReaderConfig{Root: root, RootPath: outside}); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed root reopened: %v", err)
			}
			if got := reader.ReadFile(context.Background(), "file.txt", ReadOptions{}); string(got.Data) != "root" {
				t.Fatal("owner close invalidated duplicate", got)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			assertClosedFD(t, readerFD)
			if got := reader.ReadFile(context.Background(), "file.txt", ReadOptions{}); !errors.Is(got.Err, os.ErrClosed) {
				t.Fatal("closed reader remained usable", got)
			}
		})
	}
}

func TestA2R1_TraversalAndReaderFailureCleanup(t *testing.T) {
	if readerWatchdog(t, "TestA2R1_TraversalAndReaderFailureCleanup") {
		return
	}
	w, err := NewSafeWalker(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := w.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(w.Root(), "file.txt"), []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ {
		_, inv, err := w.WalkRoot(ctx, root)
		if !errors.Is(err, context.Canceled) || inv.InventoryComplete {
			t.Fatal(inv, err)
		}
		if n := rootDescriptorCount(t, root); n != 1 {
			t.Fatalf("cancelled traversal leaked root descriptors: %d", n)
		}
		// A new independent directory offset must still enumerate on the next walk.
		files, inv, err := w.WalkRoot(context.Background(), root)
		if err != nil || !inv.InventoryComplete || len(files) != 2 {
			t.Fatal(files, inv, err)
		}
		r, err := NewGuardedReader(ReaderConfig{Root: root})
		if err != nil {
			t.Fatal(err)
		}
		fd := int(r.(*guardedReaderUnix).rootFile.Fd())
		if got := r.ReadFile(ctx, "file.txt", ReadOptions{}); !errors.Is(got.Err, context.Canceled) || got.BytesRead != 0 {
			t.Fatal(got)
		}
		if got := r.ReadFile(context.Background(), "missing", ReadOptions{}); got.Status != ReadStatusError {
			t.Fatal(got)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		assertClosedFD(t, fd)
		if n := rootDescriptorCount(t, root); n != 1 {
			t.Fatalf("traversal/reader failure leaked root descriptors: %d", n)
		}
	}
	fd := int(root.file.Fd())
	root.Close()
	assertClosedFD(t, fd)
	_, inv, err := w.WalkRoot(context.Background(), root)
	if !errors.Is(err, ErrRootSetupFailed) || inv.InventoryComplete {
		t.Fatal(inv, err)
	}
}
