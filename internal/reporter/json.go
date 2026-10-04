package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

// JSON renders scan results as machine-readable JSON.
type JSON struct {
	Writer     io.Writer
	Pretty     bool // Use indented formatting
	AppVersion string
}

// NewJSON creates a JSON reporter that writes to stdout with pretty formatting.
func NewJSON() *JSON {
	return &JSON{
		Writer:     os.Stdout,
		Pretty:     true,
		AppVersion: "0.1.0-dev",
	}
}

// jsonReport is the top-level JSON output structure.
type jsonReport struct {
	Schema    string            `json:"schema"`
	Timestamp string            `json:"timestamp"`
	Version   string            `json:"version"`
	Repo      jsonRepo          `json:"repository"`
	Summary   jsonSummary       `json:"summary"`
	Findings  []finding.Finding `json:"findings"`
	Errors    []jsonError       `json:"errors,omitempty"`
}

type jsonRepo struct {
	Root string `json:"root"`
}

type jsonSummary struct {
	TotalFindings         int            `json:"total_findings"`
	ChecksRun             int            `json:"checks_run"`
	SecurityRisk          string         `json:"security_risk"`
	MaxSeverity           string         `json:"max_severity"`
	SecurityFindingsCount int            `json:"security_findings_count"`
	HygieneFindingsCount  int            `json:"hygiene_findings_count"`
	InfoFindingsCount     int            `json:"info_findings_count"`
	BySeverity            map[string]int `json:"by_severity"`
	ByClass               map[string]int `json:"by_class"`
}

type jsonError struct {
	CheckID string `json:"check_id"`
	Message string `json:"message"`
}

func (j *JSON) Report(result *engine.ScanResult) error {
	counts := finding.CountBySeverity(result.Findings)
	bySeverity := make(map[string]int, len(counts))
	for sev, count := range counts {
		bySeverity[sev.String()] = count
	}

	classCounts := finding.CountByClass(result.Findings)
	byClass := make(map[string]int, len(classCounts))
	for cls, count := range classCounts {
		byClass[string(cls)] = count
	}

	maxSec, hasSec := finding.MaxSecuritySeverity(result.Findings)
	secRisk := "none"
	if hasSec {
		secRisk = maxSec.String()
	}

	ver := j.AppVersion
	if ver == "" {
		ver = "0.1.0-dev"
	}

	report := jsonReport{
		Schema:    "hammerhead/v0.1",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   ver,
		Repo: jsonRepo{
			Root: result.RepoRoot,
		},
		Summary: jsonSummary{
			TotalFindings:         len(result.Findings),
			ChecksRun:             result.ChecksRun,
			SecurityRisk:          secRisk,
			MaxSeverity:           finding.MaxSeverity(result.Findings).String(),
			SecurityFindingsCount: classCounts[finding.ClassSecurity],
			HygieneFindingsCount:  classCounts[finding.ClassHygiene],
			InfoFindingsCount:     classCounts[finding.ClassInfo],
			BySeverity:            bySeverity,
			ByClass:               byClass,
		},
		Findings: result.Findings,
	}

	// Ensure findings is always an array, never null.
	if report.Findings == nil {
		report.Findings = []finding.Finding{}
	}

	for _, e := range result.Errors {
		report.Errors = append(report.Errors, jsonError{
			CheckID: e.CheckID,
			Message: e.Err.Error(),
		})
	}

	var data []byte
	var err error
	if j.Pretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		return fmt.Errorf("marshaling JSON report: %w", err)
	}

	data = append(data, '\n')
	_, err = j.Writer.Write(data)
	return err
}
