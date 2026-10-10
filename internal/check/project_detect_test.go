package check_test

import (
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/finding"
)

func TestProjectDetectCheck_MultiEcosystem(t *testing.T) {
	c := &check.ProjectDetectCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "go.mod", IsDir: false},
			{Path: "frontend/package.json", IsDir: false},
			{Path: "deploy/Dockerfile", IsDir: false},
			{Path: "infra/main.tf", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 runtime findings, got %d", len(findings))
	}

	foundGo := false
	foundNode := false
	foundDocker := false
	foundTerraform := false

	for _, f := range findings {
		if f.Severity != finding.SeverityInfo {
			t.Errorf("expected SeverityInfo for all runtime detections, got %v", f.Severity)
		}
		if f.Category != finding.CategoryProject {
			t.Errorf("expected CategoryProject, got %v", f.Category)
		}

		if strings.Contains(f.Title, "Go") {
			foundGo = true
		}
		if strings.Contains(f.Title, "Node.js") {
			foundNode = true
		}
		if strings.Contains(f.Title, "Docker") {
			foundDocker = true
		}
		if strings.Contains(f.Title, "Terraform") {
			foundTerraform = true
		}
	}

	if !foundGo || !foundNode || !foundDocker || !foundTerraform {
		t.Errorf("missing expected ecosystem: go=%v, node=%v, docker=%v, tf=%v", foundGo, foundNode, foundDocker, foundTerraform)
	}
}

func TestProjectDetectCheck_Undetermined(t *testing.T) {
	c := &check.ProjectDetectCheck{}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "notes.txt", IsDir: false},
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for undetermined project, got %d: %+v", len(findings), findings)
	}
}
