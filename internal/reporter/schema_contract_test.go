package reporter_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

// Contract models independent of production structs.
type ContractThreshold struct {
	FailOn   string `json:"fail_on"`
	Exceeded bool   `json:"exceeded"`
}

type ContractRepository struct {
	Root string `json:"root"`
}

type ContractSummary struct {
	FindingsCount           int64          `json:"findings_count"`
	ClassCounts             map[string]int `json:"class_counts"`
	HighestSecuritySeverity string         `json:"highest_security_severity"`
	ChecksAttempted         int64          `json:"checks_attempted"`
}

type ContractFinding struct {
	RuleID      string `json:"rule_id"`
	Class       string `json:"class"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Evidence    string `json:"evidence"`
}

type ContractPolicy struct {
	Exclusions      []string         `json:"exclusions"`
	EffectiveLimits map[string]int64 `json:"effective_limits"`
}

type ContractTraversal struct {
	ExaminedEntries       *int64 `json:"examined_entries"`
	DiscoveredFiles       *int64 `json:"discovered_files"`
	DiscoveredDirectories *int64 `json:"discovered_directories"`
	InventoryComplete     *bool  `json:"inventory_complete"`
	RootListingComplete   *bool  `json:"root_listing_complete"`
}

type ContractReasonCount struct {
	Code              string   `json:"code"`
	Count             int64    `json:"count"`
	CountIsLowerBound bool     `json:"count_is_lower_bound"`
	Examples          []string `json:"examples"`
}

type ContractCheck struct {
	RuleID         string                `json:"rule_id"`
	CheckVer       *string               `json:"check_ver"`
	Status         string                `json:"status"`
	EligibleFiles  *int64                `json:"eligible_files"`
	InspectedFiles *int64                `json:"inspected_files"`
	ReadBytes      *int64                `json:"read_bytes"`
	ReasonCounts   []ContractReasonCount `json:"reason_counts"`
}

type ContractCoverage struct {
	Policy                    ContractPolicy        `json:"policy"`
	Traversal                 ContractTraversal     `json:"traversal"`
	Reasons                   []ContractReasonCount `json:"reasons"`
	Checks                    []ContractCheck       `json:"checks"`
	FindingsRetained          int64                 `json:"findings_retained"`
	FindingsTruncated         bool                  `json:"findings_truncated"`
	DiagnosticExamplesOmitted int64                 `json:"diagnostic_examples_omitted"`
}

type ContractDiagnostic struct {
	Stage       string `json:"stage"`
	Code        string `json:"code"`
	RuleID      string `json:"rule_id,omitempty"`
	Path        string `json:"path,omitempty"`
	SafeMessage string `json:"safe_message"`
}

type ContractResult struct {
	Schema      string               `json:"schema"`
	Status      string               `json:"status"`
	Threshold   ContractThreshold    `json:"threshold"`
	Repository  ContractRepository   `json:"repository"`
	Version     string               `json:"version"`
	Timestamp   string               `json:"timestamp"`
	Summary     ContractSummary      `json:"summary"`
	Findings    []ContractFinding    `json:"findings"`
	Coverage    ContractCoverage     `json:"coverage"`
	Diagnostics []ContractDiagnostic `json:"diagnostics"`
}

func ValidateContract(result ContractResult) []error {
	var errs []error

	if result.Schema != "hammerhead-core/v0.2" {
		errs = append(errs, fmt.Errorf("expected schema 'hammerhead-core/v0.2', got '%s'", result.Schema))
	}

	validStatuses := map[string]bool{
		"completed": true,
		"partial":   true,
		"failed":    true,
		"cancelled": true,
	}
	if !validStatuses[result.Status] {
		errs = append(errs, fmt.Errorf("invalid status: '%s'", result.Status))
	}

	validFailOn := map[string]bool{
		"high":     true,
		"critical": true,
		"none":     true,
	}
	if !validFailOn[result.Threshold.FailOn] {
		errs = append(errs, fmt.Errorf("invalid fail_on: '%s'", result.Threshold.FailOn))
	}

	if result.Threshold.FailOn == "none" && result.Threshold.Exceeded {
		errs = append(errs, fmt.Errorf("threshold.exceeded must be false if fail_on is 'none'"))
	}

	if result.Repository.Root == "" {
		errs = append(errs, fmt.Errorf("repository.root must not be empty"))
	}

	if result.Version == "" {
		errs = append(errs, fmt.Errorf("version must not be empty"))
	}

	if _, err := time.Parse(time.RFC3339, result.Timestamp); err != nil {
		errs = append(errs, fmt.Errorf("timestamp must be valid RFC3339, got: %v", err))
	}

	if result.Findings == nil {
		errs = append(errs, fmt.Errorf("findings should be an empty array, not null"))
	}

	if result.Diagnostics == nil {
		errs = append(errs, fmt.Errorf("diagnostics should be an empty array, not null"))
	}

	if result.Coverage.Checks == nil {
		errs = append(errs, fmt.Errorf("coverage.checks should be an empty array, not null"))
	}

	if result.Coverage.Reasons == nil {
		errs = append(errs, fmt.Errorf("coverage.reasons should be an empty array, not null"))
	}

	validCheckStatuses := map[string]bool{
		"completed":      true,
		"partial":        true,
		"failed":         true,
		"cancelled":      true,
		"not_applicable": true,
		"unavailable":    true,
		"not_run":        true,
	}
	validReasonCodes := map[string]bool{
		"user_cancelled":        true,
		"deadline_exceeded":     true,
		"invalid_root":          true,
		"eligible_read_failure": true,
		"budget_exhaustion":     true,
		"git_timeout":           true,
		"git_failure":           true,
		"git_unavailable":       true,
		"check_failure":         true,
		"traversal_failure":     true,
	}

	for _, chk := range result.Coverage.Checks {
		if !validCheckStatuses[chk.Status] {
			errs = append(errs, fmt.Errorf("invalid check status: '%s'", chk.Status))
		}
		if chk.CheckVer == nil {
			errs = append(errs, fmt.Errorf("check_ver must not be null in final contract"))
		}
		if chk.EligibleFiles == nil || chk.InspectedFiles == nil || chk.ReadBytes == nil {
			errs = append(errs, fmt.Errorf("check numeric fields must not be null in final contract"))
		} else if *chk.EligibleFiles < 0 || *chk.InspectedFiles < 0 || *chk.ReadBytes < 0 {
			errs = append(errs, fmt.Errorf("check numeric fields must be non-negative"))
		}
		if chk.ReasonCounts == nil {
			errs = append(errs, fmt.Errorf("reason_counts should be empty array, not null"))
		}
		for _, rc := range chk.ReasonCounts {
			if !validReasonCodes[rc.Code] {
				errs = append(errs, fmt.Errorf("invalid reason code in check coverage: '%s'", rc.Code))
			}
			if rc.Count < 0 {
				errs = append(errs, fmt.Errorf("reason count must be non-negative"))
			}
		}
	}

	for _, r := range result.Coverage.Reasons {
		if !validReasonCodes[r.Code] {
			errs = append(errs, fmt.Errorf("invalid reason code in coverage.reasons: '%s'", r.Code))
		}
	}

	if result.Coverage.Traversal.ExaminedEntries == nil ||
		result.Coverage.Traversal.DiscoveredFiles == nil ||
		result.Coverage.Traversal.DiscoveredDirectories == nil ||
		result.Coverage.Traversal.InventoryComplete == nil ||
		result.Coverage.Traversal.RootListingComplete == nil {
		errs = append(errs, fmt.Errorf("traversal coverage fields must not be null in final contract"))
	} else if *result.Coverage.Traversal.ExaminedEntries < 0 ||
		*result.Coverage.Traversal.DiscoveredFiles < 0 ||
		*result.Coverage.Traversal.DiscoveredDirectories < 0 {
		errs = append(errs, fmt.Errorf("traversal numeric fields must be non-negative"))
	}

	if result.Coverage.FindingsRetained < 0 || result.Coverage.DiagnosticExamplesOmitted < 0 {
		errs = append(errs, fmt.Errorf("coverage numeric fields must be non-negative"))
	}

	if int64(len(result.Findings)) != result.Coverage.FindingsRetained {
		errs = append(errs, fmt.Errorf("findings array length (%d) must match coverage.findings_retained (%d)", len(result.Findings), result.Coverage.FindingsRetained))
	}

	if int64(len(result.Findings)) != result.Summary.FindingsCount {
		errs = append(errs, fmt.Errorf("findings array length (%d) must match summary.findings_count (%d)", len(result.Findings), result.Summary.FindingsCount))
	}

	if result.Summary.ChecksAttempted < 0 {
		errs = append(errs, fmt.Errorf("summary.checks_attempted must be non-negative"))
	}

	requiredLimits := []string{
		"max_depth", "max_retained_inventory_entries", "directory_batch_entries",
		"max_names_per_directory", "max_examined_entries", "max_native_read_bytes",
		"sec001_max_eligible_bytes", "max_aggregate_native_read_bytes", "max_findings_retained",
		"max_diagnostic_samples", "max_examples_per_reason", "max_diagnostic_path_bytes",
		"max_safe_message_bytes", "max_finding_path_bytes", "max_evidence_bytes",
		"max_title_bytes", "max_description_bytes", "max_remediation_bytes",
		"overall_scan_timeout_ms", "symlink_resolution_steps",
	}

	for _, limit := range requiredLimits {
		val, exists := result.Coverage.Policy.EffectiveLimits[limit]
		if !exists {
			errs = append(errs, fmt.Errorf("missing required effective limit: %s", limit))
		} else if val <= 0 {
			errs = append(errs, fmt.Errorf("effective limit %s must be positive, got %d", limit, val))
		}
	}

	for _, d := range result.Diagnostics {
		if d.Stage == "" || d.Code == "" || d.SafeMessage == "" {
			errs = append(errs, fmt.Errorf("diagnostics must have stage, code, and safe_message"))
		}
		if !validReasonCodes[d.Code] {
			errs = append(errs, fmt.Errorf("invalid reason code in diagnostics: '%s'", d.Code))
		}
	}

	return errs
}

func calculateExitCode(status string, threshold ContractThreshold) int {
	if status == "partial" || status == "failed" || status == "cancelled" || status == "invalid" {
		return 2
	}
	if status == "completed" {
		if threshold.Exceeded && threshold.FailOn != "none" {
			return 1
		}
		return 0
	}
	return 2
}

func TestExitMatrix(t *testing.T) {
	tests := []struct {
		status   string
		failOn   string
		exceeded bool
		expected int
	}{
		{"completed", "high", false, 0},
		{"completed", "high", true, 1},
		{"completed", "critical", true, 1},
		{"completed", "none", false, 0},
		{"partial", "none", false, 2},
		{"partial", "high", true, 2},
		{"failed", "none", false, 2},
		{"cancelled", "high", false, 2},
		{"invalid", "high", false, 2},
		{"", "high", false, 2},
	}

	for _, tt := range tests {
		actual := calculateExitCode(tt.status, ContractThreshold{FailOn: tt.failOn, Exceeded: tt.exceeded})
		if actual != tt.expected {
			t.Errorf("calculateExitCode(%s, {failOn:%s, exceeded:%v}) = %d, expected %d", tt.status, tt.failOn, tt.exceeded, actual, tt.expected)
		}
	}
}

func TestV02ContractExamples(t *testing.T) {
	pattern := filepath.Join("..", "..", "testdata", "contracts", "v0.2", "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("failed to glob v0.2 contract examples: %v", err)
	}

	expectedFiles := map[string]int{
		"completed_clean.json":     0,
		"completed_threshold.json": 1,
		"partial_zero.json":        2,
		"partial_critical.json":    2,
		"partial_nofail.json":      2,
		"failed.json":              2,
		"cancelled.json":           2,
	}

	foundCount := 0
	for _, file := range files {
		name := filepath.Base(file)
		expectedExit, ok := expectedFiles[name]
		if !ok {
			t.Errorf("unexpected fixture found: %s", name)
			continue
		}
		foundCount++

		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			var result ContractResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			if errs := ValidateContract(result); len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("validation error: %v", e)
				}
			}

			actualExit := calculateExitCode(result.Status, result.Threshold)
			if actualExit != expectedExit {
				t.Errorf("expected exit code %d for fixture %s, got %d", expectedExit, name, actualExit)
			}
		})
	}

	if foundCount != len(expectedFiles) {
		t.Errorf("expected %d contract fixtures, found %d", len(expectedFiles), foundCount)
	}
}

func TestNegativeContractValidation(t *testing.T) {
	tests := []struct {
		name        string
		modifier    func(*ContractResult)
		expectError string
	}{
		{
			name: "invalid schema",
			modifier: func(r *ContractResult) {
				r.Schema = "hammerhead/v0.1"
			},
			expectError: "expected schema 'hammerhead-core/v0.2', got 'hammerhead/v0.1'",
		},
		{
			name: "invalid status",
			modifier: func(r *ContractResult) {
				r.Status = "success"
			},
			expectError: "invalid status: 'success'",
		},
		{
			name: "invalid fail_on",
			modifier: func(r *ContractResult) {
				r.Threshold.FailOn = "low"
			},
			expectError: "invalid fail_on: 'low'",
		},
		{
			name: "fail_on none but exceeded true",
			modifier: func(r *ContractResult) {
				r.Threshold.FailOn = "none"
				r.Threshold.Exceeded = true
			},
			expectError: "threshold.exceeded must be false if fail_on is 'none'",
		},
		{
			name: "empty repository root",
			modifier: func(r *ContractResult) {
				r.Repository.Root = ""
			},
			expectError: "repository.root must not be empty",
		},
		{
			name: "empty version",
			modifier: func(r *ContractResult) {
				r.Version = ""
			},
			expectError: "version must not be empty",
		},
		{
			name: "invalid timestamp",
			modifier: func(r *ContractResult) {
				r.Timestamp = "not-a-timestamp"
			},
			expectError: "timestamp must be valid RFC3339",
		},
		{
			name: "invalid check status",
			modifier: func(r *ContractResult) {
				r.Coverage.Checks = []ContractCheck{{Status: "skipped"}}
			},
			expectError: "invalid check status: 'skipped'",
		},
		{
			name: "findings retained mismatch",
			modifier: func(r *ContractResult) {
				r.Findings = []ContractFinding{{}}
				r.Coverage.FindingsRetained = 0
				r.Summary.FindingsCount = 1
			},
			expectError: "must match coverage.findings_retained",
		},
		{
			name: "summary findings mismatch",
			modifier: func(r *ContractResult) {
				r.Findings = []ContractFinding{{}}
				r.Coverage.FindingsRetained = 1
				r.Summary.FindingsCount = 0
			},
			expectError: "must match summary.findings_count",
		},
		{
			name: "negative numeric fields",
			modifier: func(r *ContractResult) {
				neg := int64(-1)
				pos := int64(0)
				b := false
				r.Coverage.Traversal.ExaminedEntries = &neg
				r.Coverage.Traversal.DiscoveredFiles = &pos
				r.Coverage.Traversal.DiscoveredDirectories = &pos
				r.Coverage.Traversal.InventoryComplete = &b
				r.Coverage.Traversal.RootListingComplete = &b
			},
			expectError: "traversal numeric fields must be non-negative",
		},
		{
			name: "missing diagnostic fields",
			modifier: func(r *ContractResult) {
				r.Diagnostics = []ContractDiagnostic{{Code: ""}}
			},
			expectError: "diagnostics must have stage, code, and safe_message",
		},
		{
			name: "missing effective limit",
			modifier: func(r *ContractResult) {
				delete(r.Coverage.Policy.EffectiveLimits, "max_depth")
			},
			expectError: "missing required effective limit: max_depth",
		},
		{
			name: "unknown reason code in check coverage",
			modifier: func(r *ContractResult) {
				ver := "1.0"
				var ef int64 = 0
				r.Coverage.Checks = []ContractCheck{{
					Status:         "completed",
					CheckVer:       &ver,
					EligibleFiles:  &ef,
					InspectedFiles: &ef,
					ReadBytes:      &ef,
					ReasonCounts:   []ContractReasonCount{{Code: "unknown_code", Count: 1}},
				}}
			},
			expectError: "invalid reason code in check coverage: 'unknown_code'",
		},
		{
			name: "unknown reason code in reasons",
			modifier: func(r *ContractResult) {
				r.Coverage.Reasons = []ContractReasonCount{{Code: "unknown_code", Count: 1}}
			},
			expectError: "invalid reason code in coverage.reasons: 'unknown_code'",
		},
		{
			name: "unknown reason code in diagnostics",
			modifier: func(r *ContractResult) {
				r.Diagnostics = []ContractDiagnostic{{Stage: "test", Code: "unknown_code", SafeMessage: "msg"}}
			},
			expectError: "invalid reason code in diagnostics: 'unknown_code'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := ContractResult{
				Schema: "hammerhead-core/v0.2",
				Status: "completed",
				Threshold: ContractThreshold{
					FailOn:   "high",
					Exceeded: false,
				},
				Repository:  ContractRepository{Root: "/test"},
				Version:     "1.0.0",
				Timestamp:   "2026-10-05T12:00:00Z",
				Summary:     ContractSummary{FindingsCount: 0, ChecksAttempted: 1},
				Findings:    []ContractFinding{},
				Diagnostics: []ContractDiagnostic{},
				Coverage: ContractCoverage{
					FindingsRetained: 0,
					Traversal: ContractTraversal{
						ExaminedEntries:       ptr(int64(0)),
						DiscoveredFiles:       ptr(int64(0)),
						DiscoveredDirectories: ptr(int64(0)),
						InventoryComplete:     ptr(true),
						RootListingComplete:   ptr(true),
					},
					Checks:  []ContractCheck{},
					Reasons: []ContractReasonCount{},
					Policy: ContractPolicy{
						EffectiveLimits: map[string]int64{
							"max_depth": 50, "max_retained_inventory_entries": 100000,
							"directory_batch_entries": 256, "max_names_per_directory": 10000,
							"max_examined_entries": 100000, "max_native_read_bytes": 10485760,
							"sec001_max_eligible_bytes": 5242880, "max_aggregate_native_read_bytes": 268435456,
							"max_findings_retained": 10000, "max_diagnostic_samples": 200,
							"max_examples_per_reason": 5, "max_diagnostic_path_bytes": 16384,
							"max_safe_message_bytes": 2048, "max_finding_path_bytes": 16384,
							"max_evidence_bytes": 2048, "max_title_bytes": 8192,
							"max_description_bytes": 8192, "max_remediation_bytes": 8192,
							"overall_scan_timeout_ms": 300000, "symlink_resolution_steps": 40,
						},
					},
				},
			}
			tt.modifier(&base)

			errs := ValidateContract(base)
			if len(errs) == 0 {
				t.Errorf("expected validation to fail for %s", tt.name)
				return
			}

			foundMsg := false
			for _, e := range errs {
				if strings.Contains(e.Error(), tt.expectError) {
					foundMsg = true
					break
				}
			}
			if !foundMsg {
				t.Errorf("expected error containing '%s', got: %v", tt.expectError, errs)
			}
		})
	}
}
