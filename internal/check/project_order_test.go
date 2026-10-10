package check_test

import (
	"encoding/json"
	"math/rand"
	"slices"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/finding"
)

func TestProjectDetect_ManifestChoiceIndependentOfInput(t *testing.T) {
	wantPaths := []string{"a/go.mod", "a/package.json", "a/Pipfile", "a/Cargo.toml", "a/build.gradle", "a/Gemfile", "a/composer.json", "a/Dockerfile", "a/main.tf"}
	wantTitles := []string{"Go", "Node.js / JavaScript / TypeScript", "Python", "Rust", "Java / JVM", "Ruby", "PHP", "Docker / Container", "Terraform / IaC"}
	var files []check.FileInfo
	for _, path := range wantPaths {
		files = append(files, check.FileInfo{Path: path}, check.FileInfo{Path: "z/" + path}, check.FileInfo{Path: "0/" + path, IsDir: true})
	}
	for _, path := range []string{"a/pyproject.toml", "a/requirements.txt", "a/setup.py", "a/pom.xml", "a/build.gradle.kts", "a/docker-compose.yml", "a/compose.yaml", "z/other.tf", "0/GO.MOD", "0/Package.json", "0/not-a-manifest"} {
		files = append(files, check.FileInfo{Path: path})
	}
	rng := rand.New(rand.NewSource(9))
	var wantJSON []byte
	for run := 0; run < 100; run++ {
		input := slices.Clone(files)
		rng.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		cov := &check.Coverage{}
		got, err := runCheckForTest(&check.ProjectDetectCheck{}, &check.ScanContext{Files: input, Coverage: cov})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(wantPaths) {
			t.Fatalf("got %d ecosystems", len(got))
		}
		for i, f := range got {
			if f.Path != wantPaths[i] || f.Title != "Project runtime: "+wantTitles[i] || f.ID != finding.GenerateID("PROJ-002", wantTitles[i]) || f.Class != finding.ClassInfo || f.Severity != finding.SeverityInfo {
				t.Fatalf("run %d ecosystem %d: %+v", run, i, f)
			}
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			wantJSON = encoded
		} else if string(encoded) != string(wantJSON) {
			t.Fatalf("shuffle %d changed findings", run)
		}
		if cov.EligibleFiles != len(files)-len(wantPaths) || cov.InspectedFiles != cov.EligibleFiles {
			t.Fatalf("eligibility changed: %+v", cov)
		}
	}
}
