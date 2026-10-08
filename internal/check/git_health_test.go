package check_test

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
)

func TestGitHealthCheck_NonGit(t *testing.T) {
	c := &check.GitHealthCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/non/git",
		Git:      &check.GitInfo{IsRepo: false},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-git directory, got %d", len(findings))
	}
}

func TestGitHealthCheck_Meta(t *testing.T) {
	c := &check.GitHealthCheck{}
	meta := c.Meta()

	if meta.ID != "GIT-002" {
		t.Errorf("expected ID GIT-002, got %s", meta.ID)
	}
}
