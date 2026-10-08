package check_test

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

func TestRepoHygieneCheck_MissingBoth(t *testing.T) {
	c := &check.RepoHygieneCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "main.go", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (README + LICENSE), got %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != finding.SeverityLow {
			t.Errorf("expected SeverityLow, got %v", f.Severity)
		}
		if f.Category != finding.CategoryProject {
			t.Errorf("expected CategoryProject, got %v", f.Category)
		}
	}
}

func TestRepoHygieneCheck_HasBoth(t *testing.T) {
	c := &check.RepoHygieneCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "README.md", IsDir: false},
			{Path: "LICENSE", IsDir: false},
			{Path: "main.go", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when both present, got %d", len(findings))
	}
}

func TestRepoHygieneCheck_AlternativeNames(t *testing.T) {
	c := &check.RepoHygieneCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "README.rst", IsDir: false},
			{Path: "COPYING", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected alternative names (README.rst, COPYING) to satisfy check, got %d", len(findings))
	}
}

func TestRepoHygieneCheck_SubdirIgnored(t *testing.T) {
	c := &check.RepoHygieneCheck{}

	// README and LICENSE in a subfolder do NOT count as root project documentation
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "subpkg/README.md", IsDir: false},
			{Path: "subpkg/LICENSE", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("subfolder README/LICENSE should not satisfy root check, got %d findings", len(findings))
	}
}
