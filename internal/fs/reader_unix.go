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
	config   ReaderConfig
	rootFile *os.File
	hooks    *readerHooks
}

// NewGuardedReader creates a rooted reader for Unix platforms.
func NewGuardedReader(config ReaderConfig) (GuardedReader, error) {
	var f *os.File
	var err error
	if config.Root != nil {
		f, _, _, err = config.Root.openDirectory()
	} else {
		var fd int
		fd, err = unix.Open(config.RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == nil {
			f = os.NewFile(uintptr(fd), config.RootPath)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open root dir: %w", err)
	}

	return &guardedReaderUnix{
		config:   config,
		rootFile: f,
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
	return r.rootFile.Close()
}

func (r *guardedReaderUnix) ReadFile(ctx context.Context, relativePath string, opts ReadOptions) ReadOutcome {
	if err := ctx.Err(); err != nil {
		return ReadOutcome{Status: ReadStatusError, Err: err}
	}
	// Consult the owning os.File, so use after Close cannot reuse a stale fd.
	rootFd := int(r.rootFile.Fd())
	if rootFd < 0 {
		return ReadOutcome{Status: ReadStatusError, Err: os.ErrClosed}
	}

	if relativePath == "" || relativePath == "." {
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("invalid path")}
	}
	if filepath.IsAbs(relativePath) {
		return ReadOutcome{Status: ReadStatusSafetyReject, Err: fmt.Errorf("absolute path not allowed")}
	}

	var resHooks *resolveHooks
	if r.hooks != nil {
		resHooks = &resolveHooks{
			beforeFstatat:    r.hooks.beforeFstatat,
			beforeOpenat:     r.hooks.beforeOpenat,
			beforeReadlinkat: r.hooks.beforeReadlinkat,
		}
	}

	fd, resolvedPath, status, err := resolvePathRelative(ctx, rootFd, relativePath, 40, r.config.IsExcluded, resHooks)
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
		return ReadOutcome{Status: ReadStatusBinary, BytesRead: actuallyRead, Err: fmt.Errorf("is a binary file")}
	}

	if err := ctx.Err(); err != nil {
		return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: err}
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
				return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: err}
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
				return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: fmt.Errorf("read: %w", err)}
			}
		}
	}

	var postStat unix.Stat_t
	if err := unix.Fstat(fd, &postStat); err != nil {
		return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: fmt.Errorf("post-fstat: %w", err)}
	}

	if stat.Size != postStat.Size || stat.Mtim != postStat.Mtim || stat.Ctim != postStat.Ctim {
		return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: fmt.Errorf("file mutated during read")}
	}

	if int64(len(finalData)) != stat.Size {
		return ReadOutcome{Status: ReadStatusError, BytesRead: actuallyRead, Err: fmt.Errorf("incomplete read: read %d bytes, expected %d", len(finalData), stat.Size)}
	}

	return ReadOutcome{Status: ReadStatusText, Data: finalData, BytesRead: actuallyRead}
}
