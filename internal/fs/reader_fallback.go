//go:build !unix && !darwin && !linux
// +build !unix,!darwin,!linux

package fs

import (
	"fmt"
)

// NewGuardedReader creates a rooted reader. On unsupported platforms it fails safely.
func NewGuardedReader(config ReaderConfig) (GuardedReader, error) {
	return nil, fmt.Errorf("guarded rooted reading is not supported on this platform")
}
