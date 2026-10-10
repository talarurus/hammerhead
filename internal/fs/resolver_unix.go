//go:build unix || darwin || linux
// +build unix darwin linux

package fs

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type resolveHooks struct {
	beforeFstatat    func(comp string)
	beforeOpenat     func(comp string)
	beforeReadlinkat func(comp string)
}

func resolvePathRelative(ctx context.Context, rootFd int, relPath string, maxSymlinks int, isExcluded func(relPath, baseName string) bool, hooks *resolveHooks) (fd int, resolvedPath string, status ReadStatus, err error) {
	if err := ctx.Err(); err != nil {
		return -1, "", ReadStatusError, err
	}

	components := strings.Split(relPath, string(filepath.Separator))
	symlinksWalked := 0

	rootDup, err := unix.Openat(rootFd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", ReadStatusError, fmt.Errorf("dup root fd: %w", err)
	}

	var rootStat unix.Stat_t
	if err := unix.Fstat(rootDup, &rootStat); err != nil {
		unix.Close(rootDup)
		return -1, "", ReadStatusError, fmt.Errorf("fstat root: %w", err)
	}

	stack := []dirEntry{{
		fd:   rootDup,
		name: ".",
		dev:  uint64(rootStat.Dev),
		ino:  uint64(rootStat.Ino),
	}}
	var logicalPath []string

	defer func() {
		if err != nil {
			for _, entry := range stack {
				unix.Close(entry.fd)
			}
		}
	}()

	validateChain := func() error {
		parentFd := rootFd
		for i := 1; i < len(stack); i++ {
			entry := stack[i]
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

	for i := 0; i < len(components); {
		if err := ctx.Err(); err != nil {
			return -1, "", ReadStatusError, err
		}

		comp := components[i]
		if comp == "" || comp == "." {
			i++
			continue
		}

		if comp == ".." {
			if len(stack) == 1 {
				return -1, "", ReadStatusSafetyReject, fmt.Errorf("path escapes root: %s", relPath)
			}
			last := stack[len(stack)-1]
			unix.Close(last.fd)
			stack = stack[:len(stack)-1]

			if len(logicalPath) > 0 {
				logicalPath = logicalPath[:len(logicalPath)-1]
			}
			i++
			continue
		}

		if errVal := validateChain(); errVal != nil {
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("pre-fstatat validation: %w", errVal)
		}

		currentTip := stack[len(stack)-1]

		if hooks != nil && hooks.beforeFstatat != nil {
			hooks.beforeFstatat(comp)
		}

		var stat unix.Stat_t
		if errStat := unix.Fstatat(currentTip.fd, comp, &stat, unix.AT_SYMLINK_NOFOLLOW); errStat != nil {
			return -1, "", ReadStatusError, fmt.Errorf("fstatat %s: %w", comp, errStat)
		}

		mode := stat.Mode & unix.S_IFMT
		isLast := (i == len(components)-1)

		if mode == unix.S_IFLNK {
			// Check alias exclusion BEFORE following
			currentLogicalPath := filepath.Join(append(logicalPath, comp)...)
			if isExcluded != nil && isExcluded(currentLogicalPath, comp) {
				return -1, "", ReadStatusSafetyReject, fmt.Errorf("symlink alias is excluded: %s", comp)
			}

			symlinksWalked++
			if symlinksWalked > maxSymlinks {
				return -1, "", ReadStatusSafetyReject, fmt.Errorf("max symlink depth exceeded")
			}

			bufSize := stat.Size
			if bufSize == 0 {
				bufSize = 256
			}
			bufSize += 1

			if hooks != nil && hooks.beforeReadlinkat != nil {
				hooks.beforeReadlinkat(comp)
			}

			buf := make([]byte, bufSize)
			n, errLnk := unix.Readlinkat(currentTip.fd, comp, buf)
			if errLnk != nil {
				return -1, "", ReadStatusError, fmt.Errorf("readlinkat: %w", errLnk)
			}

			if int64(n) >= bufSize {
				bufSize *= 2
				buf = make([]byte, bufSize)
				n, errLnk = unix.Readlinkat(currentTip.fd, comp, buf)
				if errLnk != nil {
					return -1, "", ReadStatusError, fmt.Errorf("readlinkat retry: %w", errLnk)
				}
				if int64(n) >= bufSize {
					return -1, "", ReadStatusSafetyReject, fmt.Errorf("readlinkat truncated target")
				}
			}
			target := string(buf[:n])

			if filepath.IsAbs(target) {
				return -1, "", ReadStatusSafetyReject, fmt.Errorf("absolute symlink escapes root: %s", target)
			}

			targetComps := strings.Split(target, string(filepath.Separator))
			newComps := make([]string, 0, len(components[:i])+len(targetComps)+len(components[i+1:]))
			newComps = append(newComps, components[:i]...)
			newComps = append(newComps, targetComps...)
			newComps = append(newComps, components[i+1:]...)
			components = newComps
			continue
		}

		if !isLast && mode != unix.S_IFDIR {
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("not a directory")
		}

		if isLast && mode != unix.S_IFREG && mode != unix.S_IFDIR {
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("unsupported special type")
		}

		currentLogicalPath := filepath.Join(append(logicalPath, comp)...)
		if isExcluded != nil && isExcluded(currentLogicalPath, comp) {
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("component is excluded: %s", comp)
		}

		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if mode == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		}

		if hooks != nil && hooks.beforeOpenat != nil {
			hooks.beforeOpenat(comp)
		}

		nextFd, errOpen := unix.Openat(currentTip.fd, comp, flags, 0)
		if errOpen != nil {
			return -1, "", ReadStatusError, fmt.Errorf("openat %s: %w", comp, errOpen)
		}

		var postStat unix.Stat_t
		if errPostStat := unix.Fstat(nextFd, &postStat); errPostStat != nil {
			unix.Close(nextFd)
			return -1, "", ReadStatusError, fmt.Errorf("post-open fstat: %w", errPostStat)
		}

		if uint64(postStat.Dev) != uint64(stat.Dev) || uint64(postStat.Ino) != uint64(stat.Ino) || (postStat.Mode&unix.S_IFMT) != mode {
			unix.Close(nextFd)
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("type or identity changed during open")
		}

		if errVal := validateChain(); errVal != nil {
			unix.Close(nextFd)
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("post-open validation: %w", errVal)
		}

		if mode == unix.S_IFDIR {
			stack = append(stack, dirEntry{
				fd:   nextFd,
				name: comp,
				dev:  uint64(postStat.Dev),
				ino:  uint64(postStat.Ino),
			})
		} else {
			for _, entry := range stack {
				unix.Close(entry.fd)
			}
			stack = nil
			resolvedPath = filepath.Join(append(logicalPath, comp)...)
			return nextFd, resolvedPath, "", nil
		}

		logicalPath = append(logicalPath, comp)
		i++
	}

	resolvedPath = filepath.Join(logicalPath...)
	if resolvedPath == "" {
		resolvedPath = "."
	}

	if len(stack) > 0 {
		finalFd := stack[len(stack)-1].fd
		for i := 0; i < len(stack)-1; i++ {
			unix.Close(stack[i].fd)
		}
		stack = nil
		return finalFd, resolvedPath, "", nil
	}

	return -1, "", ReadStatusError, fmt.Errorf("unexpected end of resolvePathRelative")
}
