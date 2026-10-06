package reporter_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
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
			Diagnostics: []scanstate.Diagnostic{
				{
					RuleID:      "GIT-001",
					SafeMessage: "failed to read .gitignore",
				},
			},
		},
		"zero-findings-error": {
			RepoRoot:  "/tmp/hammerhead-test-root",
			ChecksRun: 7,
			Findings:  []finding.Finding{},
			Diagnostics: []scanstate.Diagnostic{
				{
					RuleID:      "GIT-001",
					SafeMessage: "failed to read .gitignore",
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

func validateKeys(t *testing.T, m map[string]string, expected []string) {
	t.Helper()
	if len(m) != len(expected) {
		t.Errorf("expected %d keys, got %d", len(expected), len(m))
	}
	for _, k := range expected {
		if _, ok := m[k]; !ok {
			t.Errorf("missing expected key: %s", k)
		}
	}
	for k := range m {
		found := false
		for _, e := range expected {
			if k == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected key: %s", k)
		}
	}
}

func TestV01JSONContract_HistoricalShape(t *testing.T) {
	expectedScenarios := []string{"empty", "mixed", "hygiene", "check-error", "zero-findings-error", "skipped"}

	for _, name := range expectedScenarios {
		t.Run(name, func(t *testing.T) {
			want := readFixture(t, name+".json")
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(want), &m); err != nil {
				t.Fatalf("Historical fixture %s is not valid JSON", name)
			}
		})
	}

	// Verify no unexpected json files exist
	files, err := os.ReadDir(filepath.Join("testdata", "v0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" && f.Name() != "manifest.json" && f.Name() != "terminal_fixtures.json" && f.Name() != "quiet_fixtures.json" {
			name := strings.TrimSuffix(f.Name(), ".json")
			found := false
			for _, e := range expectedScenarios {
				if name == e {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("unexpected json fixture file: %s", f.Name())
			}
		}
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

func TestV01Manifest_HistoricalShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "v0.1", "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read manifest: %v", err)
	}

	var manifest map[string]struct {
		JSON     string `json:"json"`
		Quiet    string `json:"quiet"`
		Terminal string `json:"terminal"`
	}

	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatalf("failed to parse manifest: %v", err)
	}

	expectedScenarios := []string{"empty", "mixed", "hygiene", "check-error", "zero-findings-error", "skipped"}
	if len(manifest) != len(expectedScenarios) {
		t.Errorf("expected %d scenarios in manifest, got %d", len(expectedScenarios), len(manifest))
	}

	for _, name := range expectedScenarios {
		if _, ok := manifest[name]; !ok {
			t.Errorf("manifest missing scenario: %s", name)
		}
	}
}

func TestV01TerminalContract_HistoricalShape(t *testing.T) {
	fixtures := readJSONFixtures(t, "terminal_fixtures.json")
	expectedScenarios := []string{"empty", "mixed", "hygiene", "check-error", "zero-findings-error", "skipped"}
	validateKeys(t, fixtures, expectedScenarios)
}

func TestV01QuietContract_HistoricalShape(t *testing.T) {
	fixtures := readJSONFixtures(t, "quiet_fixtures.json")
	expectedScenarios := []string{"empty", "mixed", "hygiene", "check-error", "zero-findings-error", "skipped"}
	validateKeys(t, fixtures, expectedScenarios)
}

func TestV01ExitContract_HistoricalShape(t *testing.T) {
	// Assert the historical zero-findings-error.json shows clean output instead of failure.
	b, err := os.ReadFile(filepath.Join("testdata", "v0.1", "zero-findings-error.json"))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	var res map[string]interface{}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, hasStatus := res["status"]; hasStatus {
		t.Errorf("v0.1 zero-findings-error.json should not have a status field")
	}
}

func TestV01ZeroFindingsErrorCharacterization_HistoricalShape(t *testing.T) {
	fixtures := readJSONFixtures(t, "terminal_fixtures.json")
	out, ok := fixtures["zero-findings-error"]
	if !ok {
		t.Fatalf("zero-findings-error missing from terminal fixtures")
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "DIAGNOSTIC") {
		t.Errorf("Expected known defect: error NOT rendered in terminal when 0 findings")
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("Expected known defect: terminal claims No findings despite errors")
	}
}

func TestV01SkippedEntriesCharacterization_HistoricalShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "v0.1", "skipped.json"))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if strings.Contains(string(b), `"skipped"`) {
		t.Errorf("Expected known defect: skipped entries absent in JSON")
	}
}
