package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/app"
	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/reporter"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func setupIntegrationEngine() *engine.Engine {
	return engine.New(engine.DefaultRegistry())
}

// 1. finding budget
func TestIntegration_FindingBudget(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	for i := 0; i < 10; i++ {
		content := "-----BEGIN RSA PRIVATE KEY-----\n"
		os.WriteFile(filepath.Join(tmpDir, "key"+string(rune('A'+i))+".pem"), []byte(content), 0644)
	}

	limits := scanstate.ProductionLimits()
	limits.MaxFindings = 3
	cfg := &engine.ScanConfig{Limits: &limits}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if res.Status != scanstate.StatusPartial {
		t.Errorf("expected status partial, got %v", res.Status)
	}

	if len(res.Findings) != 3 {
		t.Errorf("expected exactly 3 findings due to budget, got %d", len(res.Findings))
	}
	if res.Coverage.FindingsTruncated != true {
		t.Errorf("expected FindingsTruncated to be true")
	}
	if res.Attempted() != 4 {
		t.Errorf("expected 4 attempts (MaxFindings + 1), got %d", res.Attempted())
	}
	if !res.AttemptedLowerBound() {
		t.Errorf("expected AttemptedLowerBound to be true")
	}

	exitCode := app.ExitCode(res, app.ThresholdPolicy{Severity: finding.SeverityHigh})
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (partial), got %d", exitCode)
	}
}

// 3. rejected threshold
func TestIntegration_RejectedThreshold(t *testing.T) {
	reg := engine.NewRegistry()
	reg.Add(&mockCheck{
		meta: check.Meta{ID: "MOCK-001"},
		findings: []finding.Finding{
			{RuleID: "MOCK-001", Title: "Low 1", Class: finding.ClassSecurity, Severity: finding.SeverityLow},
			{RuleID: "MOCK-001", Title: "Med 1", Class: finding.ClassSecurity, Severity: finding.SeverityMedium},
			{RuleID: "MOCK-001", Title: "Crit 1", Class: finding.ClassSecurity, Severity: finding.SeverityCritical},
		},
	})

	eng := engine.New(reg)
	tmpDir := t.TempDir()

	limits := scanstate.ProductionLimits()
	limits.MaxFindings = 2
	cfg := &engine.ScanConfig{Limits: &limits}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if res.Status != scanstate.StatusPartial {
		t.Errorf("expected status partial, got %v", res.Status)
	}

	if len(res.Findings) != 2 {
		t.Errorf("expected 2 findings retained")
	} else {
		if res.Findings[0].Severity != finding.SeverityMedium && res.Findings[1].Severity != finding.SeverityMedium {
			t.Errorf("expected Medium to be retained")
		}
	}

	sev, hasSec := res.HighestObservedSecuritySeverity()
	if !hasSec || sev != finding.SeverityCritical {
		t.Errorf("expected highest observed security to be Critical even though it was rejected, got %v", sev)
	}

	if !res.ThresholdExceeded(finding.SeverityHigh) {
		t.Errorf("expected ThresholdExceeded(High) to be true")
	}

	highExit := app.ExitCode(res, app.ThresholdPolicy{Severity: finding.SeverityHigh})
	if highExit != 2 {
		t.Errorf("expected High policy exit to be 2, got %d", highExit)
	}

	noneExit := app.ExitCode(res, app.ThresholdPolicy{Disabled: true})
	if noneExit != 2 {
		t.Errorf("expected FailOnNone exit to be 2 (due to partial status), got %d", noneExit)
	}

	// Test JSON Reporter
	var buf bytes.Buffer
	rep := reporter.NewJSON()
	rep.Writer = &buf
	rep.FailOn = finding.SeverityHigh

	if err := rep.Report(res); err != nil {
		t.Fatalf("JSON Render failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	thresh := parsed["threshold"].(map[string]interface{})
	if thresh["fail_on"] != "high" {
		t.Errorf("expected fail_on high, got %v", thresh["fail_on"])
	}
	if thresh["exceeded"] != true {
		t.Errorf("expected threshold.exceeded true")
	}

	summary := parsed["summary"].(map[string]interface{})
	if summary["highest_security_severity"] != "critical" {
		t.Errorf("expected highest_security_severity critical, got %v", summary["highest_security_severity"])
	}
	if summary["findings_count"].(float64) != 2 {
		t.Errorf("expected findings_count 2, got %v", summary["findings_count"])
	}

	findingsList := parsed["findings"].([]interface{})
	if len(findingsList) != 2 {
		t.Errorf("expected 2 findings serialized, got %d", len(findingsList))
	}

	// Test none policy with JSON
	buf.Reset()
	repNone := reporter.NewJSON()
	repNone.Writer = &buf
	repNone.FailOnNone = true
	repNone.FailOn = finding.SeverityHigh // Set but disabled by FailOnNone

	if err := repNone.Report(res); err != nil {
		t.Fatalf("JSON Render failed: %v", err)
	}
	var parsedNone map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsedNone); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	threshNone := parsedNone["threshold"].(map[string]interface{})
	if threshNone["exceeded"] != false {
		t.Errorf("expected none policy to have exceeded=false")
	}
}

// 4. diagnostic samples
func TestIntegration_DiagnosticSamples(t *testing.T) {
	tmpDir := t.TempDir()
	reg := engine.NewRegistry()

	// Create 10 mock checks that each fail
	for i := 0; i < 10; i++ {
		reg.Add(&mockDiagCheck{id: "MOCK-" + string(rune('A'+i))})
	}

	engDiag := engine.New(reg)

	limits := scanstate.ProductionLimits()
	limits.MaxDiagnosticSamples = 3
	limits.MaxExamplesPerReason = 3
	cfg := &engine.ScanConfig{Limits: &limits}

	res, err := engDiag.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var foundReason *scanstate.Reason
	for i, r := range res.Coverage.Reasons {
		if r.Code == scanstate.ReasonCheckFailure {
			foundReason = &res.Coverage.Reasons[i]
			break
		}
	}

	if foundReason == nil {
		t.Fatalf("expected ReasonCheckFailure reason")
	}

	if foundReason.Count != 10 {
		t.Errorf("expected aggregate count to be 10, got %d", foundReason.Count)
	}

	diagCount := 0
	for _, d := range res.Diagnostics {
		if d.Code == scanstate.ReasonCheckFailure {
			diagCount++
		}
	}
	if diagCount > 3 {
		t.Errorf("expected max 3 diagnostics, got %d", diagCount)
	}
}

type mockDiagCheck struct {
	id string
}

func (m *mockDiagCheck) Meta() check.Meta {
	return check.Meta{ID: m.id}
}
func (m *mockDiagCheck) Run(ctx context.Context, sc *check.ScanContext) error {
	return errors.New("diagnostic error")
}

// 5. aggregate reads
func TestIntegration_AggregateReads(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	for i := 0; i < 3; i++ {
		// Write valid text so secrets.go reads it
		content := make([]byte, 1024*1024)
		for j := range content {
			content[j] = 'A'
		}
		os.WriteFile(filepath.Join(tmpDir, "file"+string(rune('A'+i))+".txt"), content, 0644)
	}

	limits := scanstate.ProductionLimits()
	limits.MaxAggregateReadBytes = 2 * 1024 * 1024
	cfg := &engine.ScanConfig{Limits: &limits}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if res.Status != scanstate.StatusPartial {
		t.Logf("Status: %v, Err: %v", res.Status, err)
		for _, d := range res.Diagnostics {
			t.Logf("Diag: %v %v", d.Code, d.SafeMessage)
		}
		for _, r := range res.Coverage.Reasons {
			t.Logf("Reason: %v %v", r.Code, r.Count)
		}
		t.Fatalf("expected partial status due to budget exhaustion")
	}

	var foundReason *scanstate.Reason
	for i, r := range res.Coverage.Reasons {
		if r.Code == scanstate.ReasonBudgetExhaustion {
			foundReason = &res.Coverage.Reasons[i]
			break
		}
	}

	if foundReason == nil {
		for _, d := range res.Diagnostics {
			if d.Code == scanstate.ReasonBudgetExhaustion {
				foundReason = &scanstate.Reason{Code: d.Code}
				break
			}
		}
	}
	if foundReason == nil {
		for _, c := range res.Coverage.Checks {
			for _, r := range c.ReasonCounts {
				if r.Code == scanstate.ReasonBudgetExhaustion {
					foundReason = &scanstate.Reason{Code: r.Code}
					break
				}
			}
		}
	}

	if foundReason == nil {
		t.Logf("Coverage reasons:")
		for _, r := range res.Coverage.Reasons {
			t.Logf("  %v: %v", r.Code, r.Count)
		}
		t.Logf("Diagnostics:")
		for _, d := range res.Diagnostics {
			t.Logf("  %v: %v", d.Code, d.SafeMessage)
		}
		t.Errorf("expected budget exhaustion due to aggregate reads")
	}
}

// 6. limit isolation / concurrent scans
func TestIntegration_LimitIsolation(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "key.pem"), []byte("-----BEGIN RSA PRIVATE KEY-----\n"), 0644)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			limits := scanstate.ProductionLimits()
			limits.MaxFindings = 1 + (i % 2)
			cfg := &engine.ScanConfig{Limits: &limits}
			res, err := eng.Scan(context.Background(), tmpDir, cfg)
			if err != nil {
				t.Errorf("Scan failed: %v", err)
			}
			if len(res.Findings) != int(limits.MaxFindings) {
				t.Errorf("expected %d findings, got %d", limits.MaxFindings, len(res.Findings))
			}
		}(i)
	}
	wg.Wait()
}

// 7. walker skips
func TestIntegration_WalkerSkips(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	// Create 10 independent trees that will be skipped (e.g. depth exceeded)
	for i := 0; i < 10; i++ {
		p := filepath.Join(tmpDir, "dir"+string(rune('A'+i)), "sub", "deep")
		os.MkdirAll(p, 0755)
		os.WriteFile(filepath.Join(p, "file.txt"), []byte("data"), 0644)
	}

	limits := scanstate.ProductionLimits()
	cfg := &engine.ScanConfig{
		Walker: &fs.WalkerConfig{
			MaxDepth: 2, // depth will be exceeded by "sub/deep"
		},
		Limits: &limits,
	}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err == nil {
		t.Fatalf("expected error due to max depth exceeded (returns StatusPartial but no error from Scan, wait walkErr is returned from Scan unless... actually Scan returns walkErr)")
	}

	skipCount := 0
	for _, s := range res.Skipped {
		if s.Category == fs.SkipCategoryDepthExceeded {
			skipCount++
		}
	}

	if skipCount > 5 {
		t.Errorf("expected max 5 skipped examples for depth exceeded, got %d", skipCount)
	}
}

// 2. fail-on none
func TestIntegration_FailOnNone(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	for i := 0; i < 5; i++ {
		content := "-----BEGIN RSA PRIVATE KEY-----\n"
		os.WriteFile(filepath.Join(tmpDir, "key"+string(rune('A'+i))+".pem"), []byte(content), 0644)
	}

	limits := scanstate.ProductionLimits()
	limits.MaxFindings = 2 // will be exhausted
	cfg := &engine.ScanConfig{Limits: &limits}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if res.Status != scanstate.StatusPartial {
		t.Errorf("expected partial status")
	}

	exitCode := app.ExitCode(res, app.ThresholdPolicy{Disabled: true})
	if exitCode != 2 {
		t.Errorf("expected fail-on none to return 2 for partial result, got %d", exitCode)
	}
}

// 8. Regression: ordinary excluded dir does not cause ReasonTraversalFailure
func TestIntegration_ExcludedDirNotTraversalFailure(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	// Create an excluded directory
	excDir := filepath.Join(tmpDir, "node_modules")
	os.MkdirAll(excDir, 0755)
	os.WriteFile(filepath.Join(excDir, "ignored.txt"), []byte("data"), 0644)

	// Normal file
	os.WriteFile(filepath.Join(tmpDir, "normal.txt"), []byte("data"), 0644)

	limits := scanstate.ProductionLimits()
	cfg := &engine.ScanConfig{
		Walker: &fs.WalkerConfig{
			ExcludePatterns: []string{"node_modules"},
		},
		Limits: &limits,
	}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if res.Status != scanstate.StatusCompleted {
		t.Errorf("expected status completed, got %v", res.Status)
	}

	for _, d := range res.Diagnostics {
		if d.Code == scanstate.ReasonTraversalFailure {
			t.Errorf("unexpected ReasonTraversalFailure diagnostic: %v", d)
		}
	}
	for _, r := range res.Coverage.Reasons {
		if r.Code == scanstate.ReasonTraversalFailure {
			t.Errorf("unexpected ReasonTraversalFailure count in reasons: %v", r)
		}
	}
}

// 9. Tiny limit enforcing traversal diagnostic inclusion
func TestIntegration_TinyDiagnosticLimitWithTraversalDiag(t *testing.T) {
	eng := setupIntegrationEngine()
	tmpDir := t.TempDir()

	// Create a deep directory to force budget exhaustion in traversal
	p := tmpDir
	for j := 0; j < 3; j++ {
		p = filepath.Join(p, "dir")
	}
	os.MkdirAll(p, 0755)
	os.WriteFile(filepath.Join(p, "file.txt"), []byte("data"), 0644)

	limits := scanstate.ProductionLimits()
	limits.MaxDiagnosticSamples = 1 // very tiny limit
	cfg := &engine.ScanConfig{
		Walker: &fs.WalkerConfig{
			MaxDepth: 2, // will exhaust
		},
		Limits: &limits,
	}

	res, err := eng.Scan(context.Background(), tmpDir, cfg)
	if err == nil {
		t.Fatalf("expected error from max depth exceeded")
	}

	// Because MaxDiagnosticSamples=1, and the walker consumed 1 sample for the depth skip,
	// the total retained samples (Diagnostics + Skipped) should not exceed 1.
	totalSamples := len(res.Diagnostics) + len(res.Skipped)
	if totalSamples > 1 {
		t.Errorf("expected max 1 total sample, got %d (Diagnostics: %d, Skipped: %d)",
			totalSamples, len(res.Diagnostics), len(res.Skipped))
	}
}
