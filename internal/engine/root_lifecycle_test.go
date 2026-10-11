//go:build darwin || linux

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

type lifecycleReader struct {
	fs.GuardedReader
	closed bool
}

func (r *lifecycleReader) Close() error { r.closed = true; return r.GuardedReader.Close() }

type lifecycleCheck struct {
	check.Check
	after func()
}

func (c lifecycleCheck) Run(ctx context.Context, sc *check.ScanContext) error {
	err := c.Check.Run(ctx, sc)
	c.after()
	return err
}

func TestA2R1_EngineLifecycle(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, kind := range []string{"normal", "reader-setup-failure", "check-failure", "cancel-after-finding", "cancel-before-checks", "partial-walk", "deadline-before-checks"} {
		t.Run(kind, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.WriteFile(filepath.Join(rootPath, "a.key"), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline-before-checks" {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, 2*time.Second)
				defer timeoutCancel()
			}
			registry := DefaultRegistry()
			if kind == "check-failure" || kind == "cancel-after-finding" {
				registry = NewRegistry()
				after := func() {}
				if kind == "cancel-after-finding" {
					after = cancel
				}
				if err := registry.Add(lifecycleCheck{Check: &check.SensitiveFileCheck{}, after: after}); err != nil {
					t.Fatal(err)
				}
				if kind == "check-failure" {
					if err := registry.Add(&lifecycleFailureCheck{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			e := New(registry)
			var root *fs.RootHandle
			var reader *lifecycleReader
			e.newReader = func(config fs.ReaderConfig) (fs.GuardedReader, error) {
				root = config.Root
				if root == nil || config.RootPath != "" {
					t.Fatal("engine supplied pathname authority")
				}
				if kind == "reader-setup-failure" {
					return nil, errors.New("synthetic reader setup failure")
				}
				r, err := fs.NewGuardedReader(config)
				if err != nil {
					return nil, err
				}
				reader = &lifecycleReader{GuardedReader: r}
				if kind == "cancel-before-checks" {
					cancel()
				}
				if kind == "deadline-before-checks" {
					<-ctx.Done()
				}
				return reader, nil
			}
			var config *ScanConfig
			if kind == "partial-walk" {
				config = &ScanConfig{Walker: &fs.WalkerConfig{MaxFiles: 1}}
			}
			result, err := e.Scan(ctx, rootPath, config)
			if result == nil || root == nil {
				t.Fatalf("lost lifecycle result: %v %v", result, err)
			}
			want := scanstate.StatusCompleted
			switch kind {
			case "reader-setup-failure", "check-failure", "partial-walk":
				want = scanstate.StatusPartial
			case "cancel-after-finding", "cancel-before-checks", "deadline-before-checks":
				want = scanstate.StatusCancelled
			}
			if kind == "deadline-before-checks" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline lost: %v", err)
			}
			if result.Status != want {
				t.Fatalf("status=%s want=%s err=%v", result.Status, want, err)
			}
			if _, err := fs.NewGuardedReader(fs.ReaderConfig{Root: root, RootPath: rootPath}); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("engine root not closed: %v", err)
			}
			if reader != nil && !reader.closed {
				t.Fatal("reader not closed")
			}
			if reader != nil {
				out := reader.ReadFile(context.Background(), "a.key", fs.ReadOptions{})
				if !errors.Is(out.Err, os.ErrClosed) {
					t.Fatal("reader authority survived scan", out)
				}
			}
			if kind != "cancel-before-checks" && kind != "deadline-before-checks" && kind != "partial-walk" {
				retained := false
				for _, f := range result.Findings {
					retained = retained || f.RuleID == "FILE-001" && f.Path == "a.key"
				}
				if !retained {
					t.Fatal("earlier finding lost", result)
				}
			}
		})
	}
}

type lifecycleFailureCheck struct{}

func (*lifecycleFailureCheck) Meta() check.Meta { return check.Meta{ID: "TEST-FAILURE"} }
func (*lifecycleFailureCheck) Run(context.Context, *check.ScanContext) error {
	return errors.New("synthetic check failure")
}

func TestA2R1_GitBindingSetupFailure(t *testing.T) {
	w, err := fs.NewSafeWalker(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := w.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	snapshot, err := collectRootGit(context.Background(), w.Root(), root)
	if err == nil || snapshot.Status != scanstate.CheckStatusPartial || snapshot.Root != "" {
		t.Fatal(snapshot, err)
	}
}
