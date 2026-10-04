package finding_test

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected finding.Severity
		wantErr  bool
	}{
		{"info", finding.SeverityInfo, false},
		{"INFO", finding.SeverityInfo, false},
		{"low", finding.SeverityLow, false},
		{"LOW", finding.SeverityLow, false},
		{"medium", finding.SeverityMedium, false},
		{"MEDIUM", finding.SeverityMedium, false},
		{"high", finding.SeverityHigh, false},
		{"HIGH", finding.SeverityHigh, false},
		{"critical", finding.SeverityCritical, false},
		{"CRITICAL", finding.SeverityCritical, false},
		{"invalid", finding.SeverityInfo, true},
		{"", finding.SeverityInfo, true},
	}

	for _, tt := range tests {
		got, err := finding.ParseSeverity(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSeverity(%q) err = %v, wantErr = %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.expected {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestSeverity_JSON(t *testing.T) {
	type wrapper struct {
		Sev finding.Severity `json:"severity"`
	}

	w := wrapper{Sev: finding.SeverityHigh}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expected := `{"severity":"high"}`
	if string(data) != expected {
		t.Errorf("got %s, want %s", string(data), expected)
	}

	var unmarshaled wrapper
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if unmarshaled.Sev != finding.SeverityHigh {
		t.Errorf("got %v, want %v", unmarshaled.Sev, finding.SeverityHigh)
	}

	// Test unmarshal error on invalid string
	err = json.Unmarshal([]byte(`{"severity":"invalid"}`), &unmarshaled)
	if err == nil {
		t.Errorf("expected error unmarshaling invalid severity, got nil")
	}
}

func TestConfidence_JSON(t *testing.T) {
	type wrapper struct {
		Conf finding.Confidence `json:"confidence"`
	}

	w := wrapper{Conf: finding.ConfidenceHigh}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expected := `{"confidence":"high"}`
	if string(data) != expected {
		t.Errorf("got %s, want %s", string(data), expected)
	}

	var unmarshaled wrapper
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if unmarshaled.Conf != finding.ConfidenceHigh {
		t.Errorf("got %v, want %v", unmarshaled.Conf, finding.ConfidenceHigh)
	}

	// Test unmarshal error on invalid confidence
	err = json.Unmarshal([]byte(`{"confidence":"unknown"}`), &unmarshaled)
	if err == nil {
		t.Errorf("expected error unmarshaling invalid confidence, got nil")
	}
}

func TestGenerateID(t *testing.T) {
	id1 := finding.GenerateID("FILE-001", "id_rsa")
	id2 := finding.GenerateID("FILE-001", "id_rsa")
	id3 := finding.GenerateID("FILE-001", ".env")

	if id1 != id2 {
		t.Errorf("GenerateID is non-deterministic: %q != %q", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("GenerateID generated collision for different paths: %q == %q", id1, id3)
	}
	if len(id1) < 10 {
		t.Errorf("GenerateID generated unexpectedly short ID: %q", id1)
	}
}

func TestBySeveritySort(t *testing.T) {
	findings := []finding.Finding{
		{Title: "Low item", Severity: finding.SeverityLow},
		{Title: "Critical item", Severity: finding.SeverityCritical},
		{Title: "High item", Severity: finding.SeverityHigh},
		{Title: "Medium item", Severity: finding.SeverityMedium},
		{Title: "Info item", Severity: finding.SeverityInfo},
	}

	sort.Sort(finding.BySeverity(findings))

	expected := []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeverityInfo,
	}

	for i, f := range findings {
		if f.Severity != expected[i] {
			t.Errorf("index %d: got severity %v, want %v", i, f.Severity, expected[i])
		}
	}
}

func TestCountBySeverityAndMax(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.SeverityLow},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityMedium},
	}

	counts := finding.CountBySeverity(findings)
	if counts[finding.SeverityHigh] != 2 {
		t.Errorf("High count = %d, want 2", counts[finding.SeverityHigh])
	}
	if counts[finding.SeverityLow] != 1 {
		t.Errorf("Low count = %d, want 1", counts[finding.SeverityLow])
	}
	if counts[finding.SeverityCritical] != 0 {
		t.Errorf("Critical count = %d, want 0", counts[finding.SeverityCritical])
	}

	max := finding.MaxSeverity(findings)
	if max != finding.SeverityHigh {
		t.Errorf("MaxSeverity = %v, want %v", max, finding.SeverityHigh)
	}

	emptyMax := finding.MaxSeverity(nil)
	if emptyMax != finding.SeverityInfo {
		t.Errorf("empty MaxSeverity = %v, want %v", emptyMax, finding.SeverityInfo)
	}
}

func TestAboveThreshold(t *testing.T) {
	findings := []finding.Finding{
		{Title: "1", Severity: finding.SeverityInfo},
		{Title: "2", Severity: finding.SeverityLow},
		{Title: "3", Severity: finding.SeverityMedium},
		{Title: "4", Severity: finding.SeverityHigh},
		{Title: "5", Severity: finding.SeverityCritical},
	}

	aboveHigh := finding.AboveThreshold(findings, finding.SeverityHigh)
	if len(aboveHigh) != 2 {
		t.Errorf("AboveThreshold(High) count = %d, want 2", len(aboveHigh))
	}

	aboveLow := finding.AboveThreshold(findings, finding.SeverityLow)
	if len(aboveLow) != 4 {
		t.Errorf("AboveThreshold(Low) count = %d, want 4", len(aboveLow))
	}
}

func TestFindingClass_AffectsSecurityRisk(t *testing.T) {
	sec := finding.Finding{Class: finding.ClassSecurity, Severity: finding.SeverityHigh}
	hyg := finding.Finding{Class: finding.ClassHygiene, Severity: finding.SeverityHigh}
	inf := finding.Finding{Class: finding.ClassInfo, Severity: finding.SeverityLow}

	if !sec.AffectsSecurityRisk() {
		t.Errorf("ClassSecurity must affect security risk")
	}
	if hyg.AffectsSecurityRisk() {
		t.Errorf("ClassHygiene must NOT affect security risk")
	}
	if inf.AffectsSecurityRisk() {
		t.Errorf("ClassInfo must NOT affect security risk")
	}
}

func TestMaxSecuritySeverity_HygieneOnly(t *testing.T) {
	findings := []finding.Finding{
		{Class: finding.ClassHygiene, Severity: finding.SeverityHigh},
		{Class: finding.ClassHygiene, Severity: finding.SeverityMedium},
		{Class: finding.ClassInfo, Severity: finding.SeverityLow},
	}

	max, hasSecurity := finding.MaxSecuritySeverity(findings)
	if hasSecurity {
		t.Errorf("expected hasSecurity=false for hygiene-only findings, got true")
	}
	if max != finding.SeverityInfo {
		t.Errorf("expected SeverityInfo for hygiene-only findings, got %v", max)
	}
}

func TestMaxSecuritySeverity_WithSecurity(t *testing.T) {
	findings := []finding.Finding{
		{Class: finding.ClassHygiene, Severity: finding.SeverityHigh},
		{Class: finding.ClassSecurity, Severity: finding.SeverityMedium},
		{Class: finding.ClassInfo, Severity: finding.SeverityLow},
	}

	max, hasSecurity := finding.MaxSecuritySeverity(findings)
	if !hasSecurity {
		t.Errorf("expected hasSecurity=true when security findings exist")
	}
	if max != finding.SeverityMedium {
		t.Errorf("expected SeverityMedium for security findings max, got %v", max)
	}
}

func TestCountByClass(t *testing.T) {
	findings := []finding.Finding{
		{Class: finding.ClassSecurity},
		{Class: finding.ClassSecurity},
		{Class: finding.ClassHygiene},
		{Class: finding.ClassInfo},
	}

	counts := finding.CountByClass(findings)
	if counts[finding.ClassSecurity] != 2 {
		t.Errorf("ClassSecurity count = %d, want 2", counts[finding.ClassSecurity])
	}
	if counts[finding.ClassHygiene] != 1 {
		t.Errorf("ClassHygiene count = %d, want 1", counts[finding.ClassHygiene])
	}
	if counts[finding.ClassInfo] != 1 {
		t.Errorf("ClassInfo count = %d, want 1", counts[finding.ClassInfo])
	}
}
