//go:build unix || darwin || linux
// +build unix darwin linux

package fs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type dirEntry struct {
	fd   int
	name string
	dev  uint64
	ino  uint64
}

type readerHooks struct {
	beforeFstatat    func(comp string)
	beforeOpenat     func(comp string)
	beforeReadlinkat func(comp string)
	beforeRead       func()
	beforeChunkRead  func()
}

type guardedReaderUnix struct {
	config ReaderConfig
	rootFd int
	hooks  *readerHooks
}

// NewGuardedReader creates a rooted reader for Unix platforms.
func NewGuardedReader(config ReaderConfig) (GuardedReader, error) {
	fd, err := unix.Open(config.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open root dir: %w", err)
	}

	return &guardedReaderUnix{
		config: config,
		rootFd: fd,
	}, nil
}

func newGuardedReaderWithHooks(config ReaderConfig, hooks *readerHooks) (GuardedReader, error) {
	r, err := NewGuardedReader(config)
	if err != nil {
		return nil, err
	}
	r.(*guardedReaderUnix).hooks = hooks
	return r, nil
}

func (r *guardedReaderUnix) Close() error {
	return unix.Close(r.rootFd)
}

func (r *guardedReaderUnix) ReadFile(ctx context.Context, relativePath string, opts ReadOptions) ReadOutcome {
	if err := ctx.Err(); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: err}
	}

	if relativePath == "" || relativePath == "." {
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("invalid path")}
	}
	if filepath.IsAbs(relativePath) {
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("absolute path not allowed")}
	}

	fd, resolvedPath, status, err := r.secureOpen(ctx, relativePath)
	if err != nil {
		return ReadOutcome{Status: status, Err: err}
	}
	defer unix.Close(fd)

	if r.config.IsExcluded != nil {
		baseName := filepath.Base(resolvedPath)
		if r.config.IsExcluded(resolvedPath, baseName) {
			return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("resolved path excluded")}
		}
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("fstat: %w", err)}
	}

	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		// allowed
	case unix.S_IFDIR:
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("is a directory")}
	default:
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("is a special file")}
	}

	limit := opts.MaxSize
	if r.config.SecurityReadLimit > 0 {
		if limit <= 0 || r.config.SecurityReadLimit < limit {
			limit = r.config.SecurityReadLimit
		}
	}
	size := stat.Size
	if limit > 0 && size > limit {
		return ReadOutcome{Status: ReadStatusTooLarge, Err: fmt.Errorf("file size %d exceeds limit %d", size, limit)}
	}

	var reserved int64
	var actuallyRead int64

	if r.config.AggregateReadBytes != nil {
		if r.config.MaxAggregate > 0 {
			for {
				currentAgg := atomic.LoadInt64(r.config.AggregateReadBytes)
				if currentAgg < 0 {
					return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("invalid aggregate counter state")}
				}
				if size > r.config.MaxAggregate-currentAgg {
					return ReadOutcome{Status: ReadStatusBudgetExhaust, Err: fmt.Errorf("aggregate read budget exhausted")}
				}
				if atomic.CompareAndSwapInt64(r.config.AggregateReadBytes, currentAgg, currentAgg+size) {
					reserved = size
					break
				}
			}
		} else {
			reserved = size
			atomic.AddInt64(r.config.AggregateReadBytes, size)
		}
	}

	defer func() {
		if r.config.AggregateReadBytes != nil && reserved > actuallyRead {
			atomic.AddInt64(r.config.AggregateReadBytes, -(reserved - actuallyRead))
		}
	}()

	dupFd, err := unix.Dup(fd)
	if err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("dup: %w", err)}
	}

	f := os.NewFile(uintptr(dupFd), relativePath)
	defer f.Close()

	if err := ctx.Err(); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: err}
	}

	probeLimit := int64(512)
	if size < probeLimit {
		probeLimit = size
	}

	if r.hooks != nil && r.hooks.beforeRead != nil {
		r.hooks.beforeRead()
	}

	probeBuf := make([]byte, probeLimit)
	var n int
	if probeLimit > 0 {
		n, err = io.ReadFull(f, probeBuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("probe read: %w", err)}
		}
		probeBuf = probeBuf[:n]
		actuallyRead += int64(n)
	}

	isBinary := false
	if n > 0 {
		contentType := http.DetectContentType(probeBuf)
		if !strings.HasPrefix(contentType, "text/") && contentType != "application/json" {
			isBinary = true
		}
	}

	if isBinary {
		return ReadOutcome{Status: ReadStatusBinary, Err: fmt.Errorf("is a binary file")}
	}

	if err := ctx.Err(); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: err}
	}

	restLimit := size - int64(n)
	var finalData []byte = probeBuf

	if restLimit > 0 {
		chunkSize := int64(32 * 1024)
		for restLimit > 0 {
			if r.hooks != nil && r.hooks.beforeChunkRead != nil {
				r.hooks.beforeChunkRead()
			}

			if err := ctx.Err(); err != nil {
				return ReadOutcome{Status: ReadStatusError, Err: err}
			}

			readSize := chunkSize
			if restLimit < readSize {
				readSize = restLimit
			}

			chunk := make([]byte, readSize)
			rn, err := f.Read(chunk)

			if rn > 0 {
				finalData = append(finalData, chunk[:rn]...)
				actuallyRead += int64(rn)
				restLimit -= int64(rn)
			}

			if err == io.EOF {
				break
			}
			if err != nil {
				return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("read: %w", err)}
			}
		}
	}

	var postStat unix.Stat_t
	if err := unix.Fstat(fd, &postStat); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("post-fstat: %w", err)}
	}

	if stat.Size != postStat.Size || stat.Mtim != postStat.Mtim || stat.Ctim != postStat.Ctim {
		return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("file mutated during read")}
	}

	if int64(len(finalData)) != stat.Size {
		return ReadOutcome{Status: ReadStatusError, Err: fmt.Errorf("incomplete read: read %d bytes, expected %d", len(finalData), stat.Size)}
	}

	return ReadOutcome{Status: ReadStatusText, Data: finalData}
}

func (r *guardedReaderUnix) secureOpen(ctx context.Context, relPath string) (fd int, resolvedPath string, status ReadStatus, err error) {
	if err := ctx.Err(); err != nil {
		return -1, "", ReadStatusError, err
	}

	components := strings.Split(relPath, string(filepath.Separator))
	symlinksWalked := 0
	maxSymlinks := 40

	rootDup, err := unix.Openat(r.rootFd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
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
		parentFd := r.rootFd
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

		if r.hooks != nil && r.hooks.beforeFstatat != nil {
			r.hooks.beforeFstatat(comp)
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
			if r.config.IsExcluded != nil && r.config.IsExcluded(currentLogicalPath, comp) {
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

			if r.hooks != nil && r.hooks.beforeReadlinkat != nil {
				r.hooks.beforeReadlinkat(comp)
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
		if r.config.IsExcluded != nil && r.config.IsExcluded(currentLogicalPath, comp) {
			return -1, "", ReadStatusSafetyReject, fmt.Errorf("component is excluded: %s", comp)
		}

		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if mode == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		}

		if r.hooks != nil && r.hooks.beforeOpenat != nil {
			r.hooks.beforeOpenat(comp)
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

	return -1, "", ReadStatusError, fmt.Errorf("unexpected end of secureOpen")
}
