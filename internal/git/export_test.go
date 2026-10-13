package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// RunTrustedFixture tests process/output ownership with a trusted mock Git.
// This API exists only in the test binary. Production Run always admits source
// metadata. Even the mock process receives private startup directories.
func (r *GitRunner) RunTrustedFixture(ctx context.Context, dir string, args ...string) (out string, resultErr error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	allocation, err := os.MkdirTemp("", "hammerhead-runner-test-")
	if err != nil {
		return "", err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(allocation)) }()
	home := filepath.Join(allocation, "home")
	gd := filepath.Join(allocation, "git")
	for _, p := range []string{home, filepath.Join(home, "xdg"), gd} {
		if err := os.Mkdir(p, 0700); err != nil {
			return "", err
		}
	}
	v := &metadataView{allocation: allocation, dir: gd, home: home, root: dir, budget: newMetadataBudget(ctx), runner: r}
	return r.runControlled(ctx, v, dir, args...)
}
