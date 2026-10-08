package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

// JSON renders scan results as machine-readable JSON v0.2.
type JSON struct {
	Writer     io.Writer
	Pretty     bool
	AppVersion string
	FailOn     finding.Severity
	FailOnNone bool
}

func NewJSON() *JSON {
	return &JSON{
		Writer:     os.Stdout,
		Pretty:     true,
		AppVersion: "0.1.0-dev",
		FailOn:     finding.SeverityHigh,
	}
}

type jsonReport struct {
	Schema      string                 `json:"schema"`
	Status      scanstate.Status       `json:"status"`
	Threshold   jsonThreshold          `json:"threshold"`
	Repository  jsonRepo               `json:"repository"`
	Version     string                 `json:"version"`
	Timestamp   string                 `json:"timestamp"`
	Summary     jsonSummary            `json:"summary"`
	Findings    []finding.Finding      `json:"findings"`
	Coverage    scanstate.Coverage     `json:"coverage"`
	Diagnostics []scanstate.Diagnostic `json:"diagnostics"`
}

type jsonThreshold struct {
	FailOn   string `json:"fail_on"`
	Exceeded bool   `json:"exceeded"`
}

type jsonRepo struct {
	Root string `json:"root"`
}

type jsonSummary struct {
	FindingsCount           int            `json:"findings_count"`
	ClassCounts             map[string]int `json:"class_counts"`
	HighestSecuritySeverity string         `json:"highest_security_severity"`
	ChecksAttempted         int            `json:"checks_attempted"`
}

func (j *JSON) Report(result *engine.ScanResult) error {
	classCounts := finding.CountByClass(result.Findings)
	byClass := make(map[string]int, len(classCounts))
	for cls, count := range classCounts {
		byClass[string(cls)] = count
	}

	maxSec, hasSec := result.HighestObservedSecuritySeverity()
	highestSec := ""
	if hasSec {
		highestSec = maxSec.String()
	}

	ver := j.AppVersion
	if ver == "" {
		ver = "0.1.0-dev"
	}

	failOnStr := "none"
	if !j.FailOnNone {
		failOnStr = j.FailOn.String()
	}

	exceeded := false
	if !j.FailOnNone {
		exceeded = result.ThresholdExceeded(j.FailOn)
	}

	diags := result.Diagnostics
	if diags == nil {
		diags = []scanstate.Diagnostic{}
	}

	// Initialize maps and slices in Coverage to prevent null in JSON
	cov := result.Coverage
	if cov.Reasons == nil {
		cov.Reasons = []scanstate.Reason{}
	}
	if cov.Checks == nil {
		cov.Checks = []scanstate.CheckCoverage{}
	}

	report := jsonReport{
		Schema: "hammerhead/v0.2",
		Status: result.Status,
		Threshold: jsonThreshold{
			FailOn:   failOnStr,
			Exceeded: exceeded,
		},
		Repository: jsonRepo{
			Root: result.RepoRoot,
		},
		Version:   ver,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary: jsonSummary{
			FindingsCount:           len(result.Findings),
			ClassCounts:             byClass,
			HighestSecuritySeverity: highestSec,
			ChecksAttempted:         result.ChecksRun,
		},
		Findings:    result.Findings,
		Coverage:    cov,
		Diagnostics: diags,
	}

	if report.Findings == nil {
		report.Findings = []finding.Finding{}
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
