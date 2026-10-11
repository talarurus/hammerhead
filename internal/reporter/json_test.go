package reporter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/reporter"
)

func TestJSON_Escaping(t *testing.T) {
	var buf bytes.Buffer
	rep := reporter.NewJSON()
	rep.Writer = &buf
	rep.Pretty = false

	res := &engine.ScanResult{
		RepoRoot: "\"/path/with/quotes\"",
		Findings: []finding.Finding{
			{
				ID:          "123",
				Path:        "newline\nfile.txt",
				Evidence:    "secret=\"\x1b[31mvalue\x1b[0m\"",
				Title:       "Tab\tand\x00null",
				Description: "Control\r\ncharacters",
				Severity:    finding.SeverityHigh,
				Class:       finding.ClassSecurity,
			},
		},
	}

	if err := rep.Report(res); err != nil {
		t.Fatalf("JSON Report failed: %v", err)
	}

	out := buf.String()

	// Valid JSON check
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("Produced invalid JSON: %v\nOutput: %s", err, out)
	}

	// Make sure it contains escaped forms, not literal newlines or quotes in strings
	if strings.Contains(out, "newline\nfile.txt") {
		t.Errorf("JSON output contains unescaped newline")
	}
	if strings.Contains(out, "\"\"/path/with/quotes\"\"") {
		t.Errorf("JSON output contains unescaped quotes")
	}
}

func TestJSON_DevelopmentVersion(t *testing.T) {
	for _, empty := range []bool{false, true} {
		var out bytes.Buffer
		rep := reporter.NewJSON()
		rep.Writer = &out
		if empty {
			rep.AppVersion = ""
		}
		if err := rep.Report(&engine.ScanResult{}); err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Version != "0.2.0-dev" {
			t.Fatalf("default/fallback version: %q", parsed.Version)
		}
	}
}

func TestJSON_FailOnNone(t *testing.T) {
	var buf bytes.Buffer
	rep := reporter.NewJSON()
	rep.Writer = &buf
	rep.Pretty = false
	rep.FailOnNone = true // simulates --fail-on none

	res := &engine.ScanResult{
		RepoRoot: ".",
		Findings: []finding.Finding{
			{
				ID:       "123",
				Severity: finding.SeverityCritical,
				Class:    finding.ClassSecurity,
			},
		},
	}

	if err := rep.Report(res); err != nil {
		t.Fatalf("JSON Report failed: %v", err)
	}

	out := buf.String()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("Produced invalid JSON: %v", err)
	}

	// We expect "fail_on": "none" and "exceeded": false in the threshold object
	val, ok := parsed["threshold"].(map[string]interface{})
	if !ok {
		t.Fatalf("Missing or invalid 'threshold' object")
	}

	if failOn, _ := val["fail_on"].(string); failOn != "none" {
		t.Errorf("expected fail_on = 'none', got %q", failOn)
	}

	if exceeded, _ := val["exceeded"].(bool); exceeded != false {
		t.Errorf("expected exceeded = false with fail-on none, got %v", exceeded)
	}
}
