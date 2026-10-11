//go:build unix || darwin || linux
// +build unix darwin linux

package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	testHookBeforeOpenDir func(childName string)
)

func stModeToFileMode(mode uint32) os.FileMode {
	var m os.FileMode = os.FileMode(mode & 0777)
	switch mode & unix.S_IFMT {
	case unix.S_IFBLK:
		m |= os.ModeDevice
	case unix.S_IFCHR:
		m |= os.ModeDevice | os.ModeCharDevice
	case unix.S_IFDIR:
		m |= os.ModeDir
	case unix.S_IFIFO:
		m |= os.ModeNamedPipe
	case unix.S_IFLNK:
		m |= os.ModeSymlink
	case unix.S_IFREG:
		// nothing
	case unix.S_IFSOCK:
		m |= os.ModeSocket
	}
	if mode&unix.S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if mode&unix.S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if mode&unix.S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	return m
}

func statRelative(chain []dirEntry, childName string) (fileMeta, error) {
	if len(chain) == 0 {
		return fileMeta{}, fmt.Errorf("empty chain")
	}
	parentFd := chain[len(chain)-1].fd
	var st unix.Stat_t
	if err := unix.Fstatat(parentFd, childName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileMeta{}, err
	}
	return fileMeta{
		dev:  uint64(st.Dev),
		ino:  uint64(st.Ino),
		mode: stModeToFileMode(uint32(st.Mode)),
		size: st.Size,
	}, nil
}

func validateChain(chain []dirEntry) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty chain")
	}
	parentFd := chain[0].fd
	for i := 1; i < len(chain); i++ {
		entry := chain[i]
		var st unix.Stat_t
		if err := unix.Fstatat(parentFd, entry.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("chain broken at %s: %w", entry.name, err)
		}
		if uint64(st.Dev) != entry.dev || uint64(st.Ino) != entry.ino || (st.Mode&unix.S_IFMT) != unix.S_IFDIR {
			return fmt.Errorf("chain tampered at %s", entry.name)
		}
		parentFd = entry.fd
	}
	return nil
}

func openDirRelative(chain []dirEntry, childName string, expected fileMeta, childAbsPath string) (*os.File, []dirEntry, fileMeta, error) {
	if testHookBeforeOpenDir != nil {
		testHookBeforeOpenDir(childName)
	}

	if err := validateChain(chain); err != nil {
		return nil, nil, fileMeta{}, fmt.Errorf("pre-open validation: %w", err)
	}

	parentFd := chain[len(chain)-1].fd

	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Openat(parentFd, childName, flags, 0)
	if err != nil {
		return nil, nil, fileMeta{}, fmt.Errorf("openat: %w", err)
	}

	f := os.NewFile(uintptr(fd), childAbsPath)
	if f == nil {
		unix.Close(fd)
		return nil, nil, fileMeta{}, fmt.Errorf("failed to create os.File")
	}

	var childStat unix.Stat_t
	if err := unix.Fstat(fd, &childStat); err != nil {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("fstat: %w", err)
	}

	if uint64(childStat.Dev) != expected.dev || uint64(childStat.Ino) != expected.ino {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("directory identity changed during traversal")
	}

	fm := fileMeta{
		dev:  uint64(childStat.Dev),
		ino:  uint64(childStat.Ino),
		mode: stModeToFileMode(uint32(childStat.Mode)),
		size: childStat.Size,
	}

	newChain := make([]dirEntry, len(chain), len(chain)+1)
	copy(newChain, chain)
	newChain = append(newChain, dirEntry{
		fd:   fd,
		name: childName,
		dev:  fm.dev,
		ino:  fm.ino,
	})

	if err := validateChain(newChain); err != nil {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("post-open validation: %w", err)
	}

	if !fm.IsDir() {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("not a directory")
	}

	return f, newChain, fm, nil
}

func openRoot(path string) (*os.File, []dirEntry, fileMeta, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, nil, fileMeta{}, fmt.Errorf("open root: %w", err)
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, nil, fileMeta{}, fmt.Errorf("failed to create os.File")
	}

	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("fstat root: %w", err)
	}

	lstat, err := os.Lstat(path)
	if err != nil {
		f.Close()
		return nil, nil, fileMeta{}, err
	}

	var lstatDev, lstatIno uint64
	if sys, ok := lstat.Sys().(*syscall.Stat_t); ok {
		lstatDev = uint64(sys.Dev)
		lstatIno = uint64(sys.Ino)
	} else if sys, ok := lstat.Sys().(*unix.Stat_t); ok {
		lstatDev = uint64(sys.Dev)
		lstatIno = uint64(sys.Ino)
	} else {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("unsupported lstat sys type")
	}

	if uint64(rootStat.Dev) != lstatDev || uint64(rootStat.Ino) != lstatIno {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("root is a symlink or tampered")
	}

	fm := fileMeta{
		dev:  uint64(rootStat.Dev),
		ino:  uint64(rootStat.Ino),
		mode: stModeToFileMode(uint32(rootStat.Mode)),
		size: rootStat.Size,
	}

	if !fm.IsDir() {
		f.Close()
		return nil, nil, fileMeta{}, fmt.Errorf("not a directory")
	}

	chain := []dirEntry{{
		fd:   fd,
		name: ".",
		dev:  fm.dev,
		ino:  fm.ino,
	}}

	return f, chain, fm, nil
}

// Open "." relative to the live authority, with an independent directory
// offset and CLOEXEC. Neither rename nor pathname substitution redirects it.
func openRootRelative(root *os.File, path string) (*os.File, []dirEntry, fileMeta, error) {
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fileMeta{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, nil, fileMeta{}, err
	}
	m := fileMeta{dev: uint64(st.Dev), ino: uint64(st.Ino), mode: stModeToFileMode(uint32(st.Mode)), size: st.Size}
	return f, []dirEntry{{fd: fd, name: ".", dev: m.dev, ino: m.ino}}, m, nil
}

func readlinkRelative(chain []dirEntry, childName string) (string, error) {
	if len(chain) == 0 {
		return "", fmt.Errorf("empty chain")
	}
	parentFd := chain[len(chain)-1].fd
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(parentFd, childName, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func resolveSymlinkRelative(ctx context.Context, chain []dirEntry, relPath, name string, isExcluded func(string, string) bool) (fileMeta, error) {
	symlinkLogicalPath := filepath.Join(relPath, name)
	targetFd, _, _, err := resolvePathRelative(ctx, chain[0].fd, symlinkLogicalPath, 40, isExcluded, nil)
	if err != nil {
		return fileMeta{}, err
	}
	defer unix.Close(targetFd)

	var targetStat unix.Stat_t
	if err := unix.Fstat(targetFd, &targetStat); err != nil {
		return fileMeta{}, err
	}

	return fileMeta{
		dev:  uint64(targetStat.Dev),
		ino:  uint64(targetStat.Ino),
		mode: stModeToFileMode(uint32(targetStat.Mode)),
		size: targetStat.Size,
	}, nil
}
