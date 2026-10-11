//go:build darwin || linux

package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Retain watched ancestors so identity checks cannot suffer reclaimed-inode
// reuse. No metadata/content is read. A setup failure makes Git incomplete.
func namespaceDirectories(path string) ([]*os.File, error) {
	var files []*os.File
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			closeNamespaceDirectories(files)
			return nil, err
		}
		files = append(files, os.NewFile(uintptr(fd), path))
		parent := filepath.Dir(path)
		if parent == path {
			return files, nil
		}
		path = parent
	}
}

func closeNamespaceDirectories(files []*os.File) error {
	var err error
	for _, f := range files {
		err = errors.Join(err, f.Close())
	}
	return err
}

func checkNamespaceDirectories(files []*os.File) error {
	for _, f := range files {
		pinned, err := f.Stat()
		if err != nil {
			return err
		}
		current, err := os.Lstat(f.Name())
		if err != nil {
			return err
		}
		if !os.SameFile(pinned, current) || !current.IsDir() {
			return fmt.Errorf("root namespace changed")
		}
	}
	return nil
}
