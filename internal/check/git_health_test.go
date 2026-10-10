package check_test

import (
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

func TestGitHealthCheck_NonGit(t *testing.T) {
	c := &check.GitHealthCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/non/git",
		Git:      &check.GitInfo{Availability: scanstate.GitAvailable, Applicability: scanstate.GitNonRepository, Status: scanstate.CheckStatusNotApplicable},
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

func TestGitHealth_UsesSnapshotOnly(t *testing.T) {
	// PATH has no executable, the root does not exist, and native reads panic.
	// Findings can only originate from the supplied data.
	t.Setenv("PATH", t.TempDir())
	snapshot := check.GitInfo{
		Availability: scanstate.GitAvailable, Applicability: scanstate.GitRoot,
		Status: scanstate.CheckStatusCompleted, BranchState: scanstate.GitBranchDetached,
		Root: "/does/not/exist", ModifiedCount: 2, UntrackedCount: 3,
	}
	sc := &check.ScanContext{RepoRoot: snapshot.Root, Git: &snapshot}
	c := &check.GitHealthCheck{}
	findings, err := runCheckForTest(c, sc)
	if err != nil || len(findings) != 2 || findings[0].Evidence != "Modified files: 2, Untracked files: 3" {
		t.Fatal(findings, err)
	}
	for _, status := range []scanstate.CheckStatus{scanstate.CheckStatusPartial, scanstate.CheckStatusUnavailable, scanstate.CheckStatusNotApplicable, scanstate.CheckStatusCancelled, ""} {
		snapshot.Status = status
		findings, err = runCheckForTest(c, sc)
		if err != nil || len(findings) != 0 {
			t.Fatal(status, findings, err)
		}
	}
	snapshot.Status = scanstate.CheckStatusCompleted
	snapshot.Applicability = scanstate.GitSubdirectory
	findings, err = runCheckForTest(c, sc)
	if err != nil || len(findings) != 0 {
		t.Fatal(findings, err)
	}
}
