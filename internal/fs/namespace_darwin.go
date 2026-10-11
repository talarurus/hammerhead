//go:build darwin

package fs

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type platformNamespaceWatch struct {
	fd      int
	dirs    []*os.File
	changed bool
}

func watchNamespace(path string) (namespaceWatch, error) {
	dirs, err := namespaceDirectories(path)
	if err != nil {
		return nil, err
	}
	fd, err := newNamespaceQueue()
	if err != nil {
		closeNamespaceDirectories(dirs)
		return nil, err
	}
	w := &platformNamespaceWatch{fd: fd, dirs: dirs}
	for _, f := range dirs {
		e := unix.Kevent_t{Ident: uint64(f.Fd()), Filter: unix.EVFILT_VNODE, Flags: unix.EV_ADD | unix.EV_CLEAR, Fflags: unix.NOTE_RENAME | unix.NOTE_DELETE | unix.NOTE_REVOKE}
		if _, err := unix.Kevent(fd, []unix.Kevent_t{e}, nil, nil); err != nil {
			w.Close()
			return nil, err
		}
	}
	return w, nil
}

func newNamespaceQueue() (int, error) {
	// Darwin has no atomic CLOEXEC flag on kqueue. Coordinate with Go's
	// fork/exec path until the new descriptor is marked close-on-exec.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Kqueue()
	if err != nil {
		return -1, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return -1, errors.Join(err, unix.Close(fd))
	}
	return fd, nil
}

func (w *platformNamespaceWatch) Check() error {
	if w.fd < 0 {
		return os.ErrClosed
	}
	if w.changed {
		return fmt.Errorf("root namespace changed during Git collection")
	}
	var events [1]unix.Kevent_t
	zero := unix.Timespec{}
	for {
		n, err := unix.Kevent(w.fd, nil, events[:], &zero)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n > 0 {
			w.changed = true
			return fmt.Errorf("root namespace changed or watch failed during Git collection")
		}
		if err := checkNamespaceDirectories(w.dirs); err != nil {
			w.changed = true
			return err
		}
		return nil
	}
}

func (w *platformNamespaceWatch) Close() error {
	if w.fd < 0 {
		return nil
	}
	err := unix.Close(w.fd)
	w.fd = -1
	err = errors.Join(err, closeNamespaceDirectories(w.dirs))
	w.dirs = nil
	return err
}
