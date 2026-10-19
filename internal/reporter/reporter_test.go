package reporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/reporter"
	"github.com/talarurus/hammerhead/internal/scanstate"
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
				Title:       "Potential SSH private key file",
				Description: "The filename matches id_rsa, a name commonly used for SSH private keys. This is a filename-only match; contents were not inspected.",
				Remediation: "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
				Path:        "keys/id_rsa",
				Evidence:    "id_rsa",
				Source:      "hammerhead",
				CheckVer:    "0.2.0",
			},
			{
				ID:          "FILE-001-5678",
				RuleID:      "FILE-001",
				Class:       finding.ClassSecurity,
				Category:    finding.CategoryFiles,
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Potential environment configuration file",
				Description: "The filename matches a supported .env naming pattern, which may indicate environment configuration. This is a filename-only match; contents were not inspected.",
				Remediation: "Review the actual contents. If sensitive information is present, keep it outside version control and add an appropriate ignore pattern. Determine whether exposure occurred before deciding on credential rotation or other recovery steps.",
				Path:        ".env",
				Evidence:    ".env",
				Source:      "hammerhead",
				CheckVer:    "0.2.0",
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
		"HAMMERHEAD CORE AUDIT",
		"Repository:  repo",
		"Checks run:  1",
		"HIGH",
		"MEDIUM",
		"[FILE-001] Potential SSH private key file",
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

func TestEngineToJSON_PartialTraversal(t *testing.T) {
	// Create a tiny repository
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("a"), 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("b"), 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file3.txt"), []byte("c"), 0644); err != nil {
		t.Fatalf("failed to write file3: %v", err)
	}

	reg := engine.NewRegistry()
	eng := engine.New(reg)

	// Set tiny limit
	cfg := &engine.ScanConfig{
		Walker: &fs.WalkerConfig{MaxFiles: 2},
	}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err == nil {
		t.Fatalf("expected operational failure, got nil")
	}

	var buf bytes.Buffer
	rep := &reporter.JSON{FailOn: finding.SeverityHigh, Writer: &buf}
	if err := rep.Report(res); err != nil {
		t.Fatalf("failed to report JSON: %v", err)
	}

	var parsed struct {
		Schema   string `json:"schema"`
		Status   string `json:"status"`
		Coverage struct {
			Reasons   []scanstate.Reason `json:"reasons"`
			Traversal struct {
				ExaminedEntries       *int  `json:"examined_entries"`
				DiscoveredFiles       *int  `json:"discovered_files"`
				DiscoveredDirectories *int  `json:"discovered_directories"`
				InventoryComplete     *bool `json:"inventory_complete"`
				RootListingComplete   *bool `json:"root_listing_complete"`
			} `json:"traversal"`
			Policy struct {
				Exclusions      []string         `json:"exclusions"`
				EffectiveLimits map[string]int64 `json:"effective_limits"`
			} `json:"policy"`
			Checks           []scanstate.CheckCoverage `json:"checks"`
			FindingsRetained int                       `json:"findings_retained"`
		} `json:"coverage"`
		Diagnostics []scanstate.Diagnostic `json:"diagnostics"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed.Schema != "hammerhead-core/v0.2" {
		t.Errorf("expected schema hammerhead-core/v0.2, got %q", parsed.Schema)
	}
	if parsed.Status != "partial" {
		t.Errorf("expected status partial, got %q", parsed.Status)
	}
	if len(parsed.Diagnostics) == 0 || parsed.Diagnostics[0].Code != scanstate.ReasonBudgetExhaustion {
		t.Errorf("expected diagnostic budget_exhaustion, got %v", parsed.Diagnostics)
	}
	foundReason := false
	for _, r := range parsed.Coverage.Reasons {
		if r.Code == scanstate.ReasonBudgetExhaustion {
			foundReason = true
		}
	}
	if !foundReason {
		t.Errorf("expected coverage.reasons to contain budget_exhaustion, got %v", parsed.Coverage.Reasons)
	}
	if parsed.Coverage.FindingsRetained != 0 {
		t.Errorf("expected 0 findings retained, got %d", parsed.Coverage.FindingsRetained)
	}
	if parsed.Coverage.Traversal.DiscoveredFiles == nil || *parsed.Coverage.Traversal.DiscoveredFiles != 1 {
		t.Errorf("expected discovered_files 1, got %v", parsed.Coverage.Traversal.DiscoveredFiles)
	}
	if parsed.Coverage.Traversal.InventoryComplete == nil || *parsed.Coverage.Traversal.InventoryComplete != false {
		t.Errorf("expected inventory_complete false, got %v", parsed.Coverage.Traversal.InventoryComplete)
	}
	if parsed.Coverage.Traversal.ExaminedEntries == nil || *parsed.Coverage.Traversal.ExaminedEntries != 3 {
		t.Errorf("expected examined_entries 3, got %v", parsed.Coverage.Traversal.ExaminedEntries)
	}
	if parsed.Coverage.Traversal.DiscoveredDirectories == nil || *parsed.Coverage.Traversal.DiscoveredDirectories != 1 {
		t.Errorf("expected discovered_directories 1, got %v", parsed.Coverage.Traversal.DiscoveredDirectories)
	}
	if parsed.Coverage.Traversal.RootListingComplete == nil || *parsed.Coverage.Traversal.RootListingComplete != true {
		t.Errorf("expected root_listing_complete true, got %v", parsed.Coverage.Traversal.RootListingComplete)
	}
	if !slices.Contains(parsed.Coverage.Policy.Exclusions, ".git") {
		t.Errorf("expected applied .git exclusion, got %v", parsed.Coverage.Policy.Exclusions)
	}
	if parsed.Coverage.Policy.EffectiveLimits == nil || len(parsed.Coverage.Policy.EffectiveLimits) == 0 {
		t.Errorf("expected effective_limits to be populated, got %v", parsed.Coverage.Policy.EffectiveLimits)
	}
}

func TestTerminalReporter_Clean(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false,
	}

	result := &engine.ScanResult{Status: scanstate.StatusCompleted,
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
	jsonRep := &reporter.JSON{FailOn: finding.SeverityHigh,
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

	if parsed.Schema != "hammerhead-core/v0.2" {
		t.Errorf("expected schema hammerhead-core/v0.2, got %q", parsed.Schema)
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
	jsonRep := &reporter.JSON{FailOn: finding.SeverityHigh,
		Writer: &buf,
		Pretty: false,
	}

	result := &engine.ScanResult{Status: scanstate.StatusCompleted,
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
	if strings.Contains(out, "HAMMERHEAD CORE AUDIT") {
		t.Errorf("quiet mode should not contain banner")
	}
	if strings.Contains(out, "Why it matters:") {
		t.Errorf("quiet mode should not contain 'Why it matters:'")
	}

	// Must contain compact lines
	if !strings.Contains(out, "[HIGH] [FILE-001] keys/id_rsa Potential SSH private key file") {
		t.Errorf("quiet mode missing compact finding line: %s", out)
	}
	if !strings.Contains(out, "[MEDIUM] [FILE-001] .env Potential environment configuration file") {
		t.Errorf("quiet mode missing compact finding line: %s", out)
	}
}

func TestTerminalReporter_HygieneOnly(t *testing.T) {
	var buf bytes.Buffer
	term := &reporter.Terminal{
		Writer: &buf,
		Color:  false,
	}

	result := &engine.ScanResult{Status: scanstate.StatusCompleted,
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
	if !strings.Contains(out, "Observed Core severity: NONE") {
		t.Errorf("expected 'Observed Core severity: NONE' for hygiene-only findings, got:\n%s", out)
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
	jsonRep := &reporter.JSON{FailOn: finding.SeverityHigh,
		Writer: &buf,
		Pretty: true,
	}

	result := &engine.ScanResult{Status: scanstate.StatusCompleted,
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
			HighestSecuritySeverity string         `json:"highest_security_severity"`
			FindingsCount           int            `json:"findings_count"`
			ClassCounts             map[string]int `json:"class_counts"`
		} `json:"summary"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Summary.HighestSecuritySeverity != "" {
		t.Errorf("expected highest_security_severity to be empty, got %q", parsed.Summary.HighestSecuritySeverity)
	}
	if parsed.Summary.ClassCounts["security"] != 0 {
		t.Errorf("expected 0 security findings, got %d", parsed.Summary.ClassCounts["security"])
	}
	if parsed.Summary.ClassCounts["hygiene"] != 1 {
		t.Errorf("expected 1 hygiene finding, got %d", parsed.Summary.ClassCounts["hygiene"])
	}
}

func TestJSON_PartialCoverage(t *testing.T) {
	var buf bytes.Buffer
	jsonRep := &reporter.JSON{FailOn: finding.SeverityHigh,
		Writer: &buf,
		Pretty: true,
	}

	ptrInt := func(i int) *int { return &i }
	ptrBool := func(b bool) *bool { return &b }

	result := &engine.ScanResult{
		Status: scanstate.StatusPartial,
		Diagnostics: []scanstate.Diagnostic{
			{Stage: "check", Code: scanstate.ReasonCheckFailure, SafeMessage: "some error"},
		},
		Coverage: scanstate.Coverage{
			Traversal: scanstate.TraversalCoverage{
				ExaminedEntries:   ptrInt(5),
				InventoryComplete: ptrBool(false),
			},
		},
	}

	if err := jsonRep.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var parsed struct {
		Schema    string `json:"schema"`
		Status    string `json:"status"`
		Threshold struct {
			FailOn string `json:"fail_on"`
		} `json:"threshold"`
		Coverage struct {
			Traversal struct {
				ExaminedEntries   int  `json:"examined_entries"`
				InventoryComplete bool `json:"inventory_complete"`
			} `json:"traversal"`
		} `json:"coverage"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"diagnostics"`
	}

	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Schema != "hammerhead-core/v0.2" {
		t.Errorf("expected schema hammerhead-core/v0.2, got %q", parsed.Schema)
	}
	if parsed.Status != "partial" {
		t.Errorf("expected status partial, got %q", parsed.Status)
	}
	if parsed.Threshold.FailOn != "high" {
		t.Errorf("expected fail_on high, got %q", parsed.Threshold.FailOn)
	}
	if parsed.Coverage.Traversal.ExaminedEntries != 5 {
		t.Errorf("expected 5 examined entries, got %d", parsed.Coverage.Traversal.ExaminedEntries)
	}
	if parsed.Coverage.Traversal.InventoryComplete {
		t.Errorf("expected InventoryComplete to be false")
	}
	if len(parsed.Diagnostics) != 1 || parsed.Diagnostics[0].Code != string(scanstate.ReasonCheckFailure) {
		t.Errorf("expected diagnostic check_failure, got %v", parsed.Diagnostics)
	}
}

func TestTerminal_ZeroFindingsWithFailure(t *testing.T) {
	var buf bytes.Buffer
	term := reporter.NewTerminal()
	term.Writer = &buf
	term.Color = false

	result := &engine.ScanResult{
		Status: scanstate.StatusPartial,
		Diagnostics: []scanstate.Diagnostic{
			{Stage: "traversal", Code: scanstate.ReasonBudgetExhaustion, SafeMessage: "hit limit"},
		},
	}

	if err := term.Report(result); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Observed Core severity: UNKNOWN") {
		t.Errorf("expected UNKNOWN security risk, got:\n%s", out)
	}
	if !strings.Contains(out, "⚠ Scan partial with no findings") {
		t.Errorf("expected partial status message, got:\n%s", out)
	}
	if !strings.Contains(out, "hit limit") {
		t.Errorf("expected diagnostic to be printed, got:\n%s", out)
	}
	if strings.Contains(out, "✓ No findings") {
		t.Errorf("expected no clean success message, got:\n%s", out)
	}

	// Test quiet mode: operational output belongs on the diagnostic stream.
	buf.Reset()
	var diagnostic bytes.Buffer
	term.DiagnosticWriter = &diagnostic
	term.Quiet = true
	if err := term.Report(result); err != nil {
		t.Fatalf("Report quiet failed: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("zero-findings quiet stdout must be empty: %s", buf.String())
	}
	outQuiet := diagnostic.String()
	if !strings.Contains(outQuiet, "[DIAGNOSTIC] hit limit") {
		t.Errorf("expected diagnostic in quiet mode, got:\n%s", outQuiet)
	}
	if !strings.Contains(outQuiet, "[STATUS] PARTIAL") {
		t.Errorf("expected status in quiet mode, got:\n%s", outQuiet)
	}
}

func TestV02JSON_MatchesGoldens(t *testing.T) {
	ptrInt := func(i int) *int { return &i }
	ptrBool := func(b bool) *bool { return &b }

	scenarios := map[string]*engine.ScanResult{
		"completed": {
			Status:    scanstate.StatusCompleted,
			RepoRoot:  "/repo",
			ChecksRun: 1,
			Findings:  []finding.Finding{},
			Coverage: scanstate.Coverage{
				FindingsRetained: 0,
				Traversal: scanstate.TraversalCoverage{
					ExaminedEntries:   ptrInt(10),
					InventoryComplete: ptrBool(true),
				},
				Checks:  []scanstate.CheckCoverage{},
				Reasons: []scanstate.Reason{},
				Policy: scanstate.PolicyCoverage{
					EffectiveLimits: map[string]int64{"max_depth": 50},
				},
			},
		},
		"partial-zero": {
			Status:    scanstate.StatusPartial,
			RepoRoot:  "/repo",
			ChecksRun: 1,
			Findings:  []finding.Finding{},
			Diagnostics: []scanstate.Diagnostic{
				{Stage: "traversal", Code: scanstate.ReasonBudgetExhaustion, SafeMessage: "hit limit"},
			},
			Coverage: scanstate.Coverage{
				FindingsRetained: 0,
				Traversal: scanstate.TraversalCoverage{
					ExaminedEntries:   ptrInt(10),
					InventoryComplete: ptrBool(false),
				},
				Checks:  []scanstate.CheckCoverage{},
				Reasons: []scanstate.Reason{{Code: scanstate.ReasonBudgetExhaustion, Count: 1, Examples: []string{}}},
				Policy: scanstate.PolicyCoverage{
					EffectiveLimits: map[string]int64{"max_depth": 50},
				},
			},
		},
		"partial-retained": {
			Status:    scanstate.StatusPartial,
			RepoRoot:  "/repo",
			ChecksRun: 1,
			Findings: []finding.Finding{
				{
					ID: "SEC-123", RuleID: "SEC-001", Severity: finding.SeverityHigh,
					Class: finding.ClassSecurity, Title: "Vuln",
				},
			},
			Diagnostics: []scanstate.Diagnostic{
				{Stage: "check", Code: scanstate.ReasonCheckFailure, SafeMessage: "check error"},
			},
			Coverage: scanstate.Coverage{
				FindingsRetained: 1,
				Traversal: scanstate.TraversalCoverage{
					ExaminedEntries:   ptrInt(10),
					InventoryComplete: ptrBool(true),
				},
				Checks:  []scanstate.CheckCoverage{},
				Reasons: []scanstate.Reason{{Code: scanstate.ReasonCheckFailure, Count: 1, Examples: []string{}}},
				Policy: scanstate.PolicyCoverage{
					EffectiveLimits: map[string]int64{"max_depth": 50},
				},
			},
		},
		"cancelled-retained": {
			Status:    scanstate.StatusCancelled,
			RepoRoot:  "/repo",
			ChecksRun: 1,
			Findings: []finding.Finding{
				{
					ID: "SEC-123", RuleID: "SEC-001", Severity: finding.SeverityHigh,
					Class: finding.ClassSecurity, Title: "Vuln",
				},
			},
			Diagnostics: []scanstate.Diagnostic{
				{Stage: "check", Code: scanstate.ReasonUserCancelled, SafeMessage: "user cancel"},
			},
			Coverage: scanstate.Coverage{
				FindingsRetained: 1,
				Traversal: scanstate.TraversalCoverage{
					ExaminedEntries:   ptrInt(10),
					InventoryComplete: ptrBool(true),
				},
				Checks:  []scanstate.CheckCoverage{},
				Reasons: []scanstate.Reason{{Code: scanstate.ReasonUserCancelled, Count: 1, Examples: []string{}}},
				Policy: scanstate.PolicyCoverage{
					EffectiveLimits: map[string]int64{"max_depth": 50},
				},
			},
		},
	}

	for _, res := range scenarios {
		for _, f := range res.Findings {
			if f.Class == finding.ClassSecurity {
				res.RecordObservedSecurity(f.Severity)
			}
		}
	}

	for name, res := range scenarios {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			jsonRep := reporter.JSON{FailOn: finding.SeverityHigh, Writer: &buf, Pretty: true}
			if err := jsonRep.Report(res); err != nil {
				t.Fatalf("failed to report: %v", err)
			}

			// Replace timestamp for stability
			var m map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			m["timestamp"] = "2026-10-05T00:00:00Z"
			stableBuf, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			filename := filepath.Join("testdata", "v0.2", name+".json")
			if os.Getenv("UPDATE_GOLDENS") == "1" {
				if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
					t.Fatalf("failed to mkdir: %v", err)
				}
				if err := os.WriteFile(filename, append(stableBuf, '\n'), 0644); err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
			} else {
				want, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("failed to read golden file %s: %v", filename, err)
				}
				if string(append(stableBuf, '\n')) != string(want) {
					t.Errorf("output mismatch for %s", name)
				}
			}
		})
	}
}
