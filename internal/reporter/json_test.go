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
