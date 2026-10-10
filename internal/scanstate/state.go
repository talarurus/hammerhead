package scanstate

// Status represents the core execution outcome of a scan.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusPartial   Status = "partial"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// CheckStatus represents the execution outcome of an individual check.
type CheckStatus string

const (
	CheckStatusCompleted     CheckStatus = "completed"
	CheckStatusPartial       CheckStatus = "partial"
	CheckStatusFailed        CheckStatus = "failed"
	CheckStatusCancelled     CheckStatus = "cancelled"
	CheckStatusNotApplicable CheckStatus = "not_applicable"
	CheckStatusUnavailable   CheckStatus = "unavailable"
	CheckStatusNotRun        CheckStatus = "not_run"
)

// ReasonCode represents bounded finite reason codes for incompleteness.
type ReasonCode string

const (
	ReasonUserCancelled       ReasonCode = "user_cancelled"
	ReasonDeadlineExceeded    ReasonCode = "deadline_exceeded"
	ReasonInvalidRoot         ReasonCode = "invalid_root"
	ReasonEligibleReadFailure ReasonCode = "eligible_read_failure"
	ReasonBudgetExhaustion    ReasonCode = "budget_exhaustion"
	ReasonGitTimeout          ReasonCode = "git_timeout"
	ReasonGitFailure          ReasonCode = "git_failure"
	ReasonCheckFailure        ReasonCode = "check_failure"
	ReasonTraversalFailure    ReasonCode = "traversal_failure"
)

// Reason is an aggregate structured record of incomplete work.
type Reason struct {
	Code              ReasonCode `json:"code"`
	Count             int        `json:"count"`
	CountIsLowerBound bool       `json:"count_is_lower_bound"`
	Examples          []string   `json:"examples"`
}

// Coverage contains detailed run completion facts.
type Coverage struct {
	Policy                    PolicyCoverage    `json:"policy"`
	Traversal                 TraversalCoverage `json:"traversal"`
	Reasons                   []Reason          `json:"reasons"`
	Checks                    []CheckCoverage   `json:"checks"`
	FindingsRetained          int               `json:"findings_retained"`
	FindingsTruncated         bool              `json:"findings_truncated"`
	DiagnosticExamplesOmitted *int              `json:"diagnostic_examples_omitted"`
}

type PolicyCoverage struct {
	Exclusions      []string         `json:"exclusions"`
	EffectiveLimits map[string]int64 `json:"effective_limits"`
}

type TraversalCoverage struct {
	ExaminedEntries       *int  `json:"examined_entries"`
	DiscoveredFiles       *int  `json:"discovered_files"`
	DiscoveredDirectories *int  `json:"discovered_directories"`
	InventoryComplete     *bool `json:"inventory_complete"`
	RootListingComplete   *bool `json:"root_listing_complete"`
}

// CheckCoverage represents per-check granular telemetry.
type CheckCoverage struct {
	RuleID         string      `json:"rule_id"`
	CheckVer       *string     `json:"check_ver"`
	Status         CheckStatus `json:"status"`
	EligibleFiles  *int        `json:"eligible_files"`
	InspectedFiles *int        `json:"inspected_files"`
	ReadBytes      *int        `json:"read_bytes"`
	ReasonCounts   []Reason    `json:"reason_counts"`
}

// Diagnostic represents a typed structure for partial/failure conditions.
type Diagnostic struct {
	Stage       string     `json:"stage"` // e.g., "setup", "traversal", "check", "git"
	Code        ReasonCode `json:"code"`
	RuleID      string     `json:"rule_id,omitempty"`
	Path        string     `json:"path,omitempty"`
	SafeMessage string     `json:"safe_message"`
}
