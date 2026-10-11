//go:build linux

package fs

import (
	"errors"
	"fmt"
	"os"

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
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		closeNamespaceDirectories(dirs)
		return nil, err
	}
	w := &platformNamespaceWatch{fd: fd, dirs: dirs}
	for _, f := range dirs {
		// /proc is used only to attach an inode watch to an already open dir.
		_, err := unix.InotifyAddWatch(fd, fmt.Sprintf("/proc/self/fd/%d", f.Fd()), unix.IN_MOVE_SELF|unix.IN_DELETE_SELF|unix.IN_UNMOUNT)
		if err != nil {
			w.Close()
			return nil, err
		}
	}
	return w, nil
}

func (w *platformNamespaceWatch) Check() error {
	if w.fd < 0 {
		return os.ErrClosed
	}
	if w.changed {
		return fmt.Errorf("root namespace changed during Git collection")
	}
	var buf [4096]byte
	for {
		n, err := unix.Read(w.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if n > 0 {
			w.changed = true
			return fmt.Errorf("root namespace changed during Git collection")
		}
		if err != unix.EAGAIN {
			w.changed = true
			return fmt.Errorf("root namespace watch failed: %w", err)
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
