package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
)

func TestGitignoreCheck_MissingFile(t *testing.T) {
	c := &check.GitignoreCheck{}

	sc := &check.ScanContext{
		RepoRoot:  "/dummy",
		Inventory: &fs.Inventory{RootGitignore: fs.PresenceAbsent},
		Files: []check.FileInfo{
			{Path: "main.go", IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusError, Err: os.ErrNotExist}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing .gitignore, got %d", len(findings))
	}
	if findings[0].Title != "Missing .gitignore file" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	if findings[0].Severity != finding.SeverityLow {
		t.Errorf("expected SeverityLow, got %v", findings[0].Severity)
	}
}

func TestGitignoreCheck_IncompleteFile(t *testing.T) {
	c := &check.GitignoreCheck{}

	content := `# Ignore build artifacts
/build/
*.exe
`

	sc := &check.ScanContext{
		RepoRoot:  "/dummy",
		Inventory: &fs.Inventory{RootGitignore: fs.PresencePresent},
		Files: []check.FileInfo{
			{Path: ".gitignore", IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should report both Environment files and Private keys missing
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for missing rules, got %d", len(findings))
	}

	titles := make([]string, len(findings))
	for i, f := range findings {
		titles[i] = f.Title
		if !strings.Contains(f.Remediation, "git rm --cached") {
			t.Errorf("remediation missing mention of already-tracked files: %s", f.Remediation)
		}
	}
}

func TestGitignoreCheck_CompleteFile(t *testing.T) {
	c := &check.GitignoreCheck{}

	// Must pass WITHOUT requiring *.pem
	content := `# Ignore secrets and keys
.env
*.key
/build/
`

	sc := &check.ScanContext{
		RepoRoot:  "/dummy",
		Inventory: &fs.Inventory{RootGitignore: fs.PresencePresent},
		Files: []check.FileInfo{
			{Path: ".gitignore", IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(content)}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for complete .gitignore without *.pem, got %d: %+v", len(findings), findings)
	}
}

func TestGitignoreCheck_PublicCertWithoutPemInGitignore(t *testing.T) {
	c := &check.GitignoreCheck{}

	// Repository commits a public certificate (cert.pem), but .gitignore does NOT contain *.pem.
	// This must NOT trigger a GIT-001 finding.
	gitignoreContent := `# Standard exclusions
.env
*.key
`

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: ".gitignore", IsDir: false},
			{Path: "certs/ca-bundle.pem", IsDir: false},
		},
		ReadFile: func(p string, maxSize int64) fs.ReadOutcome {
			if p == ".gitignore" {
				return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte(gitignoreContent)}
			}
			return fs.ReadOutcome{Status: fs.ReadStatusText, Data: []byte("-----BEGIN CERTIFICATE-----\n...")}
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 GIT-001 findings for repo with public .pem cert when .env and *.key are present, got %d: %+v", len(findings), findings)
	}
}
