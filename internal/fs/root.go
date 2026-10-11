package fs

import (
	"fmt"
	"os"
	"sync"
)

// RootHandle owns the live object selected before inventory traversal. Stages
// borrow it only to open independent descriptor-relative directory handles.
// Close is idempotent; a closed handle never falls back to its pathname.
type RootHandle struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func (w *SafeWalker) OpenRoot() (*RootHandle, error) {
	f, _, _, err := openRoot(w.root)
	if err != nil {
		return nil, err
	}
	return &RootHandle{file: f, path: w.root}, nil
}

func (r *RootHandle) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *RootHandle) openDirectory() (*os.File, []dirEntry, fileMeta, error) {
	if r == nil {
		return nil, nil, fileMeta{}, fmt.Errorf("missing root authority")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil, nil, fileMeta{}, os.ErrClosed
	}
	return openRootRelative(r.file, r.path)
}

// PathGuard observes rename/removal of the root and its pathname ancestors
// while pathname-based Git collection runs. It is not a content snapshot.
// Watch setup/overflow/errors fail closed for Git, not for native access.
type PathGuard struct {
	root  *RootHandle
	watch namespaceWatch
}

func (r *RootHandle) GuardPath() (*PathGuard, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil, os.ErrClosed
	}
	w, err := watchNamespace(r.path)
	if err != nil {
		return nil, err
	}
	g := &PathGuard{root: r, watch: w}
	if err := g.checkPathLocked(); err != nil {
		w.Close()
		return nil, err
	}
	return g, nil
}

func (g *PathGuard) checkPathLocked() error {
	if g.root.file == nil {
		return os.ErrClosed
	}
	if err := g.watch.Check(); err != nil {
		return err
	}
	selected, err := g.root.file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat(g.root.path)
	if err != nil {
		return err
	}
	if !os.SameFile(selected, current) {
		return fmt.Errorf("root pathname changed")
	}
	return g.watch.Check()
}

func (g *PathGuard) Check() error {
	g.root.mu.Lock()
	defer g.root.mu.Unlock()
	return g.checkPathLocked()
}

func (g *PathGuard) Close() error {
	g.root.mu.Lock()
	defer g.root.mu.Unlock()
	return g.watch.Close()
}

type namespaceWatch interface {
	Check() error
	Close() error
}
