//go:build !unix && !darwin && !linux
// +build !unix,!darwin,!linux

package fs

import (
	"context"
	"fmt"
	"os"
)

var (
	testHookBeforeOpenDir func(childName string)
)

type dirEntry struct{}

func statRelative(chain []dirEntry, childName string) (fileMeta, error) {
	return fileMeta{}, fmt.Errorf("safe directory traversal is not supported on this platform")
}

func openDirRelative(chain []dirEntry, childName string, expected fileMeta, childAbsPath string) (*os.File, []dirEntry, fileMeta, error) {
	return nil, nil, fileMeta{}, fmt.Errorf("safe directory traversal is not supported on this platform")
}

func openRoot(path string) (*os.File, []dirEntry, fileMeta, error) {
	return nil, nil, fileMeta{}, fmt.Errorf("safe directory traversal is not supported on this platform")
}

func validateChain(chain []dirEntry) error {
	return nil
}

func readlinkRelative(chain []dirEntry, childName string) (string, error) {
	return "", fmt.Errorf("safe directory traversal is not supported on this platform")
}

func resolveSymlinkRelative(ctx context.Context, chain []dirEntry, relPath, name string, isExcluded func(string, string) bool) (fileMeta, error) {
	return fileMeta{}, fmt.Errorf("safe symlink resolution is not supported on this platform")
}
