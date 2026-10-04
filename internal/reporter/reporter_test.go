package reporter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/reporter"
)

func sampleScanResult() *engine.ScanResult {
	return &engine.ScanResult{
		RepoRoot:  "/test/repo",
		ChecksRun: 1,
		Findings: []finding.Finding{
			{
				ID:          "FILE-001-1234",
				RuleID:      "FILE-001",
				Class:       finding.ClassSecurity,
				Category:    finding.CategoryFiles,
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Title:       "SSH private key committed",
				Description: "An SSH key was found committed to the repository.",
				Remediation: "Remove the file and rotate keys.",
				Path:        "keys/id_rsa",
				Evidence:    "id_rsa",
				Source:      "hammerhead",
				CheckVer:    "0.1.0",
			},
			{
				ID:          "FILE-001-5678",
				RuleID:      "FILE-001",
				Class:       finding.ClassSecurity,
				Category:    finding.CategoryFiles,
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Environment file committed",
				Description: "A .env file was found.",
				Remediation: "Add .env to .gitignore.",
				Path:        ".env",
				Evidence:    ".env",
				Source:      "hammerhead",
				CheckVer:    "0.1.0",
			},
		},
	}
}

func TestTerminalReporter_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false, // Plain text for assertions
	}

	result := sampleScanResult()
	if err := term.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	out := buf.String()

	// Assertions on terminal output structure
	expectedSnippets := []string{
		"HAMMERHEAD SECURITY AUDIT",
		"Repository:  repo",
		"Checks run:  1",
		"HIGH",
		"MEDIUM",
		"[FILE-001] SSH private key committed",
		"Location:     keys/id_rsa",
		"Why it matters:",
		"Remediation:",
		"2 finding(s) in 1 check(s)",
	}

	for _, s := range expectedSnippets {
		if !strings.Contains(out, s) {
			t.Errorf("terminal output missing expected snippet: %q", s)
		}
	}
}

func TestTerminalReporter_Clean(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false,
	}

	result := &engine.ScanResult{
		RepoRoot:  "/clean/repo",
		ChecksRun: 1,
		Findings:  nil,
	}

	if err := term.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No findings") {
		t.Errorf("clean report missing 'No findings' indicator: %s", out)
	}
}

func TestJSONReporter_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	jsonRep := &reporter.JSON{
		Writer: &buf,
		Pretty: true,
	}

	result := sampleScanResult()
	if err := jsonRep.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	// Must be valid JSON
	var parsed struct {
		Schema   string            `json:"schema"`
		Summary  map[string]any    `json:"summary"`
		Findings []finding.Finding `json:"findings"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON output invalid: %v\nOutput was: %s", err, buf.String())
	}

	if parsed.Schema != "hammerhead/v0.1" {
		t.Errorf("expected schema hammerhead/v0.1, got %q", parsed.Schema)
	}
	if len(parsed.Findings) != 2 {
		t.Errorf("expected 2 findings in JSON, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].RuleID != "FILE-001" {
		t.Errorf("expected rule ID FILE-001, got %q", parsed.Findings[0].RuleID)
	}
}

func TestJSONReporter_EmptyFindingsArray(t *testing.T) {
	var buf bytes.Buffer
	jsonRep := &reporter.JSON{
		Writer: &buf,
		Pretty: false,
	}

	result := &engine.ScanResult{
		RepoRoot:  "/clean/repo",
		ChecksRun: 1,
		Findings:  nil, // nil slice
	}

	if err := jsonRep.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var parsed struct {
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Findings == nil {
		t.Errorf("empty findings must be serialized as [] rather than null")
	}
}

func TestTerminalReporter_QuietMode(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false,
		Quiet:  true,
	}

	result := sampleScanResult()
	if err := term.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	out := buf.String()
	// Must NOT contain verbose headers or descriptions
	if strings.Contains(out, "HAMMERHEAD SECURITY AUDIT") {
		t.Errorf("quiet mode should not contain banner")
	}
	if strings.Contains(out, "Why it matters:") {
		t.Errorf("quiet mode should not contain 'Why it matters:'")
	}

	// Must contain compact lines
	if !strings.Contains(out, "[HIGH] [FILE-001] keys/id_rsa SSH private key committed") {
		t.Errorf("quiet mode missing compact finding line: %s", out)
	}
	if !strings.Contains(out, "[MEDIUM] [FILE-001] .env Environment file committed") {
		t.Errorf("quiet mode missing compact finding line: %s", out)
	}
}

func TestTerminalReporter_HygieneOnly(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false,
	}

	result := &engine.ScanResult{
		RepoRoot:  "/hygiene/repo",
		ChecksRun: 2,
		Findings: []finding.Finding{
			{
				ID:       "PROJ-001-readme",
				RuleID:   "PROJ-001",
				Class:    finding.ClassHygiene,
				Severity: finding.SeverityLow,
				Title:    "Missing project README",
				Path:     "README.md",
			},
		},
	}

	if err := term.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	out := buf.String()
	// Security risk must explicitly be NONE
	if !strings.Contains(out, "Security risk:          NONE") {
		t.Errorf("expected 'Security risk:          NONE' for hygiene-only findings, got:\n%s", out)
	}
	if !strings.Contains(out, "Security findings:      0") {
		t.Errorf("expected 'Security findings:      0', got:\n%s", out)
	}
	if !strings.Contains(out, "Hygiene observations:   1") {
		t.Errorf("expected 'Hygiene observations:   1', got:\n%s", out)
	}
	if !strings.Contains(out, "HYGIENE OBSERVATIONS") {
		t.Errorf("expected HYGIENE OBSERVATIONS group header, got:\n%s", out)
	}
}

func TestJSONReporter_SecurityRiskHygieneOnly(t *testing.T) {
	var buf bytes.Buffer
	jsonRep := &reporter.JSON{
		Writer: &buf,
		Pretty: true,
	}

	result := &engine.ScanResult{
		RepoRoot:  "/hygiene/repo",
		ChecksRun: 2,
		Findings: []finding.Finding{
			{
				ID:       "PROJ-001-readme",
				RuleID:   "PROJ-001",
				Class:    finding.ClassHygiene,
				Severity: finding.SeverityLow,
				Title:    "Missing project README",
				Path:     "README.md",
			},
		},
	}

	if err := jsonRep.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var parsed struct {
		Summary struct {
			SecurityRisk          string `json:"security_risk"`
			TotalFindings         int    `json:"total_findings"`
			SecurityFindingsCount int    `json:"security_findings_count"`
			HygieneFindingsCount  int    `json:"hygiene_findings_count"`
		} `json:"summary"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Summary.SecurityRisk != "none" {
		t.Errorf("expected security_risk to be 'none', got %q", parsed.Summary.SecurityRisk)
	}
	if parsed.Summary.SecurityFindingsCount != 0 {
		t.Errorf("expected 0 security findings, got %d", parsed.Summary.SecurityFindingsCount)
	}
	if parsed.Summary.HygieneFindingsCount != 1 {
		t.Errorf("expected 1 hygiene finding, got %d", parsed.Summary.HygieneFindingsCount)
	}
}
