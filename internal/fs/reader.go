package fs

import (
	"context"
)

// ReadStatus indicates the result of a guarded read attempt.
type ReadStatus string

const (
	ReadStatusText          ReadStatus = "text"
	ReadStatusBinary        ReadStatus = "binary"
	ReadStatusTooLarge      ReadStatus = "too_large"
	ReadStatusBudgetExhaust ReadStatus = "budget_exhaust"
	// SafetyReject is an expected policy rejection, such as an excluded target
	// or unsupported type. Detected identity/ancestor failures use Error.
	ReadStatusSafetyReject ReadStatus = "safety_reject"
	// Error means required reading could not complete, including detected mutation.
	ReadStatusError ReadStatus = "error"
)

// ReadOutcome contains the safe read result.
type ReadOutcome struct {
	Status    ReadStatus
	Data      []byte
	BytesRead int64
	Err       error
}

// ReadOptions controls a single content read.
type ReadOptions struct {
	MaxSize int64
}

// GuardedReader provides bounded, rooted content access.
type GuardedReader interface {
	ReadFile(ctx context.Context, relativePath string, opts ReadOptions) ReadOutcome
	Close() error
}

// ReaderConfig holds configuration for creating a GuardedReader.
type ReaderConfig struct {
	// Root is borrowed during construction; the reader owns an independent
	// descriptor derived from it. When supplied, RootPath is never opened.
	Root *RootHandle
	// RootPath selects an initial authority for standalone reader callers only.
	RootPath           string
	AggregateReadBytes *int64
	MaxAggregate       int64
	SecurityReadLimit  int64
	IsExcluded         func(relPath, baseName string) bool
}
