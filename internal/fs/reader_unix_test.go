//go:build unix || darwin || linux
// +build unix darwin linux

package fs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReader_Cancellation(t *testing.T) {
	tmp := t.TempDir()
	content := make([]byte, 512+32768+100) // probe + 1 chunk + remainder
	for i := range content {
		content[i] = 'A'
	}
	os.WriteFile(filepath.Join(tmp, "file.txt"), content, 0644)

	ctx, cancel := context.WithCancel(context.Background())

	agg := int64(0)
	hooks := &readerHooks{
		beforeChunkRead: func() {
			cancel()
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp, AggregateReadBytes: &agg, MaxAggregate: int64(len(content) * 2)}, hooks)
	defer r.Close()

	out := r.ReadFile(ctx, "file.txt", ReadOptions{MaxSize: int64(len(content))})
	if out.Status != ReadStatusError || out.Err != context.Canceled {
		t.Fatalf("expected context.Canceled error, got %v: %v", out.Status, out.Err)
	}

	// Probe (512) bytes should be the only thing added to aggregate, since the chunk read is cancelled BEFORE f.Read
	// Or maybe probe + 0 chunks? The hook cancels before f.Read.
	// But it actually read the probe. So agg == 512.
	if agg != 512 {
		t.Fatalf("expected 512 bytes read, got %d", agg)
	}
}

func TestReader_BudgetExhaustionShortenedProbe(t *testing.T) {
	tmp := t.TempDir()
	content := make([]byte, 1024)
	os.WriteFile(filepath.Join(tmp, "file.txt"), content, 0644)

	agg := int64(1024 - 100) // 924 bytes used out of 1024 max -> 100 remaining
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp, AggregateReadBytes: &agg, MaxAggregate: 1024})
	defer r.Close()

	out := r.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 2048})
	if out.Status != ReadStatusBudgetExhaust {
		t.Fatalf("expected budget exhaust, got %v: %v", out.Status, out.Err)
	}
}

func TestReader_SameHandleProbeAndRead(t *testing.T) {
	tmp := t.TempDir()
	content := make([]byte, 2048)
	for i := range content {
		content[i] = 'A' + byte(i%26)
	}
	os.WriteFile(filepath.Join(tmp, "file.txt"), content, 0644)

	agg := int64(0)
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp, AggregateReadBytes: &agg, MaxAggregate: 4096})
	defer r.Close()

	out := r.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 4096})
	if out.Status != ReadStatusText {
		t.Fatalf("expected text, got %v: %v", out.Status, out.Err)
	}
	if string(out.Data) != string(content) {
		t.Fatalf("content mismatch")
	}
	if agg != 2048 {
		t.Fatalf("expected 2048 bytes aggregated, got %d", agg)
	}
}

func TestReader_AncestorSwapOutsideRoot(t *testing.T) {
	tmp := t.TempDir()
	outside := t.TempDir()

	os.MkdirAll(filepath.Join(tmp, "dir"), 0755)
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("inside"), 0644)
	os.WriteFile(filepath.Join(outside, "file.txt"), []byte("outside sentinel"), 0644)
	os.MkdirAll(filepath.Join(tmp, "dir", "subdir"), 0755)

	hooks := &readerHooks{
		beforeFstatat: func(comp string) {
			if comp == "subdir" {
				if err := os.Rename(filepath.Join(tmp, "dir"), filepath.Join(outside, "dir_swapped")); err != nil {
					t.Fatalf("rename failed: %v", err)
				}
			}
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp}, hooks)
	defer r.Close()

	out := r.ReadFile(context.Background(), "dir/subdir/../../file.txt", ReadOptions{MaxSize: 100})
	if string(out.Data) == "outside sentinel" {
		t.Fatalf("read outside sentinel!")
	}
	if out.Status != ReadStatusSafetyReject {
		t.Fatalf("expected safety reject from reparent, got %v: %v", out.Status, out.Err)
	}
}

func TestReader_ReplacementWithFIFO(t *testing.T) {
	if readerWatchdog(t, "TestReader_ReplacementWithFIFO") {
		return
	}
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("reg"), 0644)

	hooks := &readerHooks{
		beforeOpenat: func(comp string) {
			if comp == "file.txt" {
				if err := os.Remove(filepath.Join(tmp, "file.txt")); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(tmp, "file.txt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp}, hooks)
	defer r.Close()

	out := r.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusSafetyReject && out.Status != ReadStatusError {
		t.Fatalf("expected reject or error, got %v: %v", out.Status, out.Err)
	}
	if out.BytesRead != 0 || len(out.Data) != 0 {
		t.Fatal("replacement FIFO content accessed")
	}
}

func TestReader_SymlinkSwapOutsideRoot(t *testing.T) {
	tmp := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside sentinel"), 0644)
	os.WriteFile(filepath.Join(tmp, "target.txt"), []byte("inside"), 0644)
	os.Symlink("target.txt", filepath.Join(tmp, "link"))

	hooks := &readerHooks{
		beforeReadlinkat: func(comp string) {
			if comp == "link" {
				os.Remove(filepath.Join(tmp, "link"))
				os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(tmp, "link"))
			}
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp}, hooks)
	defer r.Close()

	out := r.ReadFile(context.Background(), "link", ReadOptions{MaxSize: 100})
	if string(out.Data) == "outside sentinel" {
		t.Fatalf("read outside sentinel!")
	}
	if out.Status != ReadStatusSafetyReject {
		t.Fatalf("expected reject, got %v: %v", out.Status, out.Err)
	}
}

func TestReader_MutationCheck(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "file.txt")
	os.WriteFile(path, []byte("data"), 0644)

	hooks := &readerHooks{
		beforeRead: func() {
			f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
			f.Write([]byte("mutated"))
			f.Close()
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp}, hooks)
	defer r.Close()

	out := r.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusError && out.Status != ReadStatusSafetyReject {
		t.Fatalf("expected error from mutation, got %v", out.Status)
	}
}

func TestReader_SocketRejected(t *testing.T) {
	if readerWatchdog(t, "TestReader_SocketRejected") {
		return
	}
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "mysock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	addr := &unix.SockaddrUnix{Name: sockPath}
	if err := unix.Bind(fd, addr); err != nil {
		t.Fatal(err)
	}

	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp})
	defer r.Close()

	out := r.ReadFile(context.Background(), "mysock", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusSafetyReject || out.BytesRead != 0 || len(out.Data) != 0 {
		t.Fatalf("expected reject, got %v", out.Status)
	}
}

func TestReader_Compat_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "empty.txt"), []byte(""), 0644)
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp})
	defer r.Close()

	out := r.ReadFile(context.Background(), "empty.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusText || len(out.Data) != 0 {
		t.Fatalf("expected empty text, got %v: %v", out.Status, out.Err)
	}
}

func TestReader_Compat_BinaryELF(t *testing.T) {
	tmp := t.TempDir()
	content := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	os.WriteFile(filepath.Join(tmp, "bin"), content, 0644)
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp})
	defer r.Close()

	out := r.ReadFile(context.Background(), "bin", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusBinary {
		t.Fatalf("expected binary, got %v: %v", out.Status, out.Err)
	}
}

func TestReader_Compat_ExactSizeBoundary(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	os.WriteFile(filepath.Join(tmp, "exact.txt"), content, 0644)
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp})
	defer r.Close()

	out := r.ReadFile(context.Background(), "exact.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusText {
		t.Fatalf("expected text, got %v", out.Status)
	}

	out2 := r.ReadFile(context.Background(), "exact.txt", ReadOptions{MaxSize: 99})
	if out2.Status != ReadStatusTooLarge {
		t.Fatalf("expected too large, got %v", out2.Status)
	}
}

func TestReader_Compat_BudgetExactFit(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	os.WriteFile(filepath.Join(tmp, "fit.txt"), content, 0644)

	agg := int64(0)
	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp, AggregateReadBytes: &agg, MaxAggregate: 100})
	defer r.Close()

	out := r.ReadFile(context.Background(), "fit.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusText {
		t.Fatalf("expected text, got %v: %v", out.Status, out.Err)
	}

	agg2 := int64(0)
	r2, _ := NewGuardedReader(ReaderConfig{RootPath: tmp, AggregateReadBytes: &agg2, MaxAggregate: 99})
	defer r2.Close()

	out2 := r2.ReadFile(context.Background(), "fit.txt", ReadOptions{MaxSize: 100})
	if out2.Status != ReadStatusBudgetExhaust {
		t.Fatalf("expected budget exhaust, got %v", out2.Status)
	}
}

func TestReader_Symlinks(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "target.txt"), []byte("data"), 0644)

	// safe relative
	os.Symlink("target.txt", filepath.Join(tmp, "safe_rel"))

	// absolute
	os.Symlink(filepath.Join(tmp, "target.txt"), filepath.Join(tmp, "abs"))

	// broken
	os.Symlink("doesntexist.txt", filepath.Join(tmp, "broken"))

	// loop
	os.Symlink("loop1", filepath.Join(tmp, "loop2"))
	os.Symlink("loop2", filepath.Join(tmp, "loop1"))

	// 40 links
	prev := "target.txt"
	for i := 1; i <= 40; i++ {
		name := fmt.Sprintf("link%d", i)
		os.Symlink(prev, filepath.Join(tmp, name))
		prev = name
	}

	// 41 links
	os.Symlink("link40", filepath.Join(tmp, "link41"))

	// relative containing ..
	os.Mkdir(filepath.Join(tmp, "dir"), 0755)
	os.Symlink("../target.txt", filepath.Join(tmp, "dir", "rel_up"))

	r, _ := NewGuardedReader(ReaderConfig{RootPath: tmp})
	defer r.Close()

	if out := r.ReadFile(context.Background(), "safe_rel", ReadOptions{MaxSize: 100}); out.Status != ReadStatusText {
		t.Fatalf("safe_rel failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "abs", ReadOptions{MaxSize: 100}); out.Status != ReadStatusSafetyReject {
		t.Fatalf("abs failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "broken", ReadOptions{MaxSize: 100}); out.Status != ReadStatusError {
		t.Fatalf("broken failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "loop1", ReadOptions{MaxSize: 100}); out.Status != ReadStatusSafetyReject {
		t.Fatalf("loop failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "link40", ReadOptions{MaxSize: 100}); out.Status != ReadStatusText {
		t.Fatalf("link40 failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "link41", ReadOptions{MaxSize: 100}); out.Status != ReadStatusSafetyReject {
		t.Fatalf("link41 failed: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "dir/rel_up", ReadOptions{MaxSize: 100}); out.Status != ReadStatusText {
		t.Fatalf("rel_up failed: %v", out.Status)
	}
}

func TestReader_ExcludedSymlinkAlias(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "safe.txt"), []byte("data"), 0644)

	os.Symlink("safe.txt", filepath.Join(tmp, "excluded_alias"))

	os.MkdirAll(filepath.Join(tmp, "excluded_dir"), 0755)
	os.Symlink("excluded_dir/../safe.txt", filepath.Join(tmp, "tricky_target"))

	r, _ := NewGuardedReader(ReaderConfig{
		RootPath: tmp,
		IsExcluded: func(relPath, baseName string) bool {
			return baseName == "excluded_alias" || baseName == "excluded_dir"
		},
	})
	defer r.Close()

	if out := r.ReadFile(context.Background(), "excluded_alias", ReadOptions{MaxSize: 100}); out.Status != ReadStatusSafetyReject {
		t.Fatalf("excluded_alias not rejected: %v", out.Status)
	}

	if out := r.ReadFile(context.Background(), "tricky_target", ReadOptions{MaxSize: 100}); out.Status != ReadStatusSafetyReject {
		t.Fatalf("tricky_target not rejected: %v", out.Status)
	}
}

func TestReader_SameTypeReplacement(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "fileA.txt"), []byte("A"), 0644)
	os.WriteFile(filepath.Join(tmp, "fileB.txt"), []byte("B"), 0644)

	hooks := &readerHooks{
		beforeOpenat: func(comp string) {
			if comp == "fileA.txt" {
				os.Rename(filepath.Join(tmp, "fileB.txt"), filepath.Join(tmp, "fileA.txt"))
			}
		},
	}
	r, _ := newGuardedReaderWithHooks(ReaderConfig{RootPath: tmp}, hooks)
	defer r.Close()

	out := r.ReadFile(context.Background(), "fileA.txt", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusSafetyReject {
		t.Fatalf("expected safety reject from same-type replacement, got %v: %v", out.Status, out.Err)
	}
}

// readerWatchdog runs potentially blocking native I/O only in a child. The
// parent kills and reaps it on timeout; the child creates no descendants.
func readerWatchdog(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("HAMMERHEAD_READER_CHILD") == name {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+name+"$")
	cmd.Env = append(os.Environ(), "HAMMERHEAD_READER_CHILD="+name)
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil || ctx.Err() != nil {
		t.Fatalf("reader child watchdog/failure: %v %v %s", err, ctx.Err(), out)
	}
	return true
}

func TestReader_FIFORejectedWithoutWriter(t *testing.T) {
	if readerWatchdog(t, "TestReader_FIFORejectedWithoutWriter") {
		return
	}
	tmp := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(tmp, "myfifo"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewGuardedReader(ReaderConfig{RootPath: tmp})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out := r.ReadFile(context.Background(), "myfifo", ReadOptions{MaxSize: 100})
	if out.Status != ReadStatusSafetyReject || out.BytesRead != 0 || len(out.Data) != 0 {
		t.Fatalf("FIFO content accessed: %+v", out)
	}
}

func TestReader_FakeDeviceMetadataRejected(t *testing.T) {
	// Synthetic metadata only: no device nodes, privilege or actual device opens.
	for _, mode := range []uint32{unix.S_IFCHR, unix.S_IFBLK} {
		meta := fileMeta{mode: stModeToFileMode(mode)}
		if meta.IsRegular() || meta.IsDir() || meta.mode&os.ModeDevice == 0 {
			t.Fatalf("device metadata admitted as a native file: %v", meta.mode)
		}
	}
}

func TestReader_SecurityReadLimitConstrains(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("1234567890")
	os.WriteFile(filepath.Join(tmp, "file.txt"), content, 0644)

	// Set an artificially low SecurityReadLimit
	r, _ := NewGuardedReader(ReaderConfig{
		RootPath:          tmp,
		SecurityReadLimit: 5,
	})
	defer r.Close()

	// If the caller doesn't specify MaxSize, it should fallback to SecurityReadLimit (5)
	out := r.ReadFile(context.Background(), "file.txt", ReadOptions{})
	if out.Status != ReadStatusTooLarge {
		t.Fatalf("expected too_large due to SecurityReadLimit, got %v", out.Status)
	}

	// If caller specifies larger MaxSize (10), SecurityReadLimit (5) should win
	out2 := r.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 10})
	if out2.Status != ReadStatusTooLarge {
		t.Fatalf("expected too_large due to SecurityReadLimit winning, got %v", out2.Status)
	}

	r2, _ := NewGuardedReader(ReaderConfig{
		RootPath:          tmp,
		SecurityReadLimit: 10,
	})
	defer r2.Close()

	// If caller specifies smaller MaxSize (3), MaxSize should win
	out3 := r2.ReadFile(context.Background(), "file.txt", ReadOptions{MaxSize: 3})
	if out3.Status != ReadStatusTooLarge {
		t.Fatalf("expected too_large due to MaxSize winning, got %v", out3.Status)
	}
}
