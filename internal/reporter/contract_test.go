package reporter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/reporter"
)

// scenarios matches the fixtures generated in testdata/v0.1.
func getScenarios() map[string]*engine.ScanResult {
	return map[string]*engine.ScanResult{
		"empty": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			Findings:  []finding.Finding{},
			ChecksRun: 7,
		},
		"mixed": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings: []finding.Finding{
				{
					RuleID:      "SEC-001",
					Title:       "Hardcoded Secret",
					Description: "A hardcoded secret was found.",
					Remediation: "Remove the secret.",
					Severity:    finding.SeverityCritical,
					Confidence:  finding.ConfidenceHigh,
					Class:       finding.ClassSecurity,
					Path:        "src/main.go",
					Line:        42,
				},
				{
					RuleID:      "PROJ-001",
					Title:       "Missing README",
					Description: "No README file found.",
					Remediation: "Add a README.",
					Severity:    finding.SeverityLow,
					Confidence:  finding.ConfidenceHigh,
					Class:       finding.ClassHygiene,
				},
				{
					RuleID:      "GIT-002",
					Title:       "Dirty Worktree",
					Description: "Uncommitted changes.",
					Remediation: "Commit or stash changes.",
					Severity:    finding.SeverityInfo,
					Confidence:  finding.ConfidenceHigh,
					Class:       finding.ClassInfo,
				},
			},
		},
		"hygiene": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings: []finding.Finding{
				{
					RuleID:      "PROJ-001",
					Title:       "Missing README",
					Description: "No README file found.",
					Remediation: "Add a README.",
					Severity:    finding.SeverityLow,
					Confidence:  finding.ConfidenceHigh,
					Class:       finding.ClassHygiene,
				},
			},
		},
		"check-error": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings: []finding.Finding{
				{
					RuleID:      "SEC-001",
					Title:       "Hardcoded Secret",
					Description: "A hardcoded secret was found.",
					Remediation: "Remove the secret.",
					Severity:    finding.SeverityCritical,
					Confidence:  finding.ConfidenceHigh,
					Class:       finding.ClassSecurity,
					Path:        "src/main.go",
					Line:        42,
				},
			},
			Errors: []engine.CheckError{
				{
					CheckID: "GIT-001",
					Err:     errors.New("failed to read .gitignore"),
				},
			},
		},
		"zero-findings-error": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings:  []finding.Finding{},
			Errors: []engine.CheckError{
				{
					CheckID: "GIT-001",
					Err:     errors.New("failed to read .gitignore"),
				},
			},
		},
		"skipped": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings:  []finding.Finding{},
			Skipped: []fs.SkippedEntry{
				{
					Path:   "large_file.bin",
					Reason: "too large",
				},
			},
		},
	}
}

func replaceTimestamp(j string) string {
	var m map[string]interface{}
	json.Unmarshal([]byte(j), &m)
	if _, ok := m["timestamp"]; ok {
		m["timestamp"] = "2026-10-05T00:00:00Z"
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return string(out) + "\n"
}

func readFixture(t *testing.T, filename string) string {
	b, err := os.ReadFile(filepath.Join("testdata", "v0.1", filename))
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", filename, err)
	}
	return string(b)
}

func TestV01JSONContract(t *testing.T) {
	scenarios := getScenarios()
	for name, res := range scenarios {
		t.Run(name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rep := reporter.NewJSON()
			rep.Writer = buf
			rep.AppVersion = "0.1.0"

			err := rep.Report(res)
			if err != nil {
				t.Fatalf("Unexpected report error: %v", err)
			}

			got := replaceTimestamp(buf.String())
			want := readFixture(t, name+".json")
			if got != want {
				t.Errorf("JSON output mismatch for %s", name)
			}
		})
	}
}

func readJSONFixtures(t *testing.T, filename string) map[string]string {
	b, err := os.ReadFile(filepath.Join("testdata", "v0.1", filename))
	if err != nil {
		t.Fatalf("Failed to read JSON fixtures %s: %v", filename, err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Failed to decode JSON fixtures %s: %v", filename, err)
	}
	return m
}

func TestV01TerminalContract(t *testing.T) {
	scenarios := getScenarios()
	fixtures := readJSONFixtures(t, "terminal_fixtures.json")
	for name, res := range scenarios {
		t.Run(name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rep := reporter.NewTerminal()
			rep.Color = false
			rep.Writer = buf

			err := rep.Report(res)
			if err != nil {
				t.Fatalf("Unexpected report error: %v", err)
			}

			got := buf.String()
			want := fixtures[name]
			if got != want {
				t.Errorf("Terminal output mismatch for %s\nGot:\n%q\nWant:\n%q", name, got, want)
			}
		})
	}
}

func TestV01QuietContract(t *testing.T) {
	scenarios := getScenarios()
	fixtures := readJSONFixtures(t, "quiet_fixtures.json")
	for name, res := range scenarios {
		t.Run(name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			rep := reporter.NewTerminal()
			rep.Color = false
			rep.Quiet = true
			rep.Writer = buf

			err := rep.Report(res)
			if err != nil {
				t.Fatalf("Unexpected report error: %v", err)
			}

			got := buf.String()
			want := fixtures[name]
			if got != want {
				t.Errorf("Quiet terminal output mismatch for %s\nGot:\n%q\nWant:\n%q", name, got, want)
			}
		})
	}
}

func TestV01ExitContract(t *testing.T) {
	scenarios := getScenarios()
	tests := []struct {
		name string
		want int
	}{
		{"empty", 0},
		{"mixed", 1},
		{"hygiene", 0},
		{"check-error", 1},
		{"zero-findings-error", 0},
		{"skipped", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := scenarios[tc.name]
			got := res.ExitCode(finding.SeverityHigh)
			if got != tc.want {
				t.Errorf("ExitCode() = %d; want %d", got, tc.want)
			}
		})
	}
}

func TestV01ZeroFindingsErrorCharacterization(t *testing.T) {
	res := getScenarios()["zero-findings-error"]

	// Characterizing known defect: 0 findings + 1 error = Exit 0
	if code := res.ExitCode(finding.SeverityHigh); code != 0 {
		t.Errorf("Expected known defect exit code 0, got %d", code)
	}

	// Ensure the error is rendered in terminal
	buf := new(bytes.Buffer)
	rep := reporter.NewTerminal()
	rep.Color = false
	rep.Writer = buf
	rep.Report(res)

	if bytes.Contains(buf.Bytes(), []byte("WARNINGS")) {
		t.Error("Expected known defect: error NOT rendered in terminal when 0 findings")
	}
}

func TestV01SkippedEntriesCharacterization(t *testing.T) {
	res := getScenarios()["skipped"]

	// Characterizing known defect: skipped entries are missing from JSON
	buf := new(bytes.Buffer)
	rep := reporter.NewJSON()
	rep.Writer = buf
	rep.AppVersion = "0.1.0"
	rep.Report(res)

	if bytes.Contains(buf.Bytes(), []byte("skipped")) {
		t.Error("Expected known defect: skipped entries absent in JSON")
	}
}
