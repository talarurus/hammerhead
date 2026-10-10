package scanstate

import (
	"errors"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

var (
	ErrBudgetExhausted = errors.New("finding budget exhausted")
	ErrPayloadTooLarge = errors.New("finding payload limit exceeded")
)

const maxInt = int(^uint(0) >> 1)

// Collector accumulates findings and diagnostics within bounded limits.
type Collector struct {
	limits                  Limits
	findings                []finding.Finding
	attempted               int
	attemptedLowerBound     bool
	exhausted               bool
	hasObservedSecurity     bool
	highestObservedSecurity finding.Severity

	diagnostics  []Diagnostic
	diagTotal    int
	diagOmitted  int
	diagExamples map[ReasonCode]int
	reasonCounts map[ReasonCode]int
}

// NewCollector creates a bounded collector.
func NewCollector(l Limits) *Collector {
	return &Collector{
		limits:       l,
		diagExamples: make(map[ReasonCode]int),
		reasonCounts: make(map[ReasonCode]int),
	}
}

// Emit attempts to record a finding. It enforces budget and payload caps.
func (c *Collector) Emit(f finding.Finding) error {
	if c.attempted < maxInt {
		c.attempted++
	} else {
		c.attemptedLowerBound = true
	}

	if f.Class == finding.ClassSecurity {
		c.hasObservedSecurity = true
		if f.Severity > c.highestObservedSecurity {
			c.highestObservedSecurity = f.Severity
		}
	}

	if len(f.Path) > c.limits.MaxFindingPath ||
		len(f.Evidence) > c.limits.MaxFindingEvidence ||
		len(f.Title) > c.limits.MaxFindingTitle ||
		len(f.Description) > c.limits.MaxFindingDesc ||
		len(f.Remediation) > c.limits.MaxFindingRemediation {
		c.exhausted = true
		c.attemptedLowerBound = true
		c.AddDiagnostic(Diagnostic{
			Stage:       "check",
			Code:        ReasonBudgetExhaustion,
			SafeMessage: "Finding payload limit exceeded",
		})
		return ErrPayloadTooLarge
	}

	if len(c.findings) >= c.limits.MaxFindings {
		c.exhausted = true
		c.attemptedLowerBound = true
		c.AddDiagnostic(Diagnostic{
			Stage:       "check",
			Code:        ReasonBudgetExhaustion,
			SafeMessage: "Finding budget exhausted",
		})
		return ErrBudgetExhausted
	}

	c.findings = append(c.findings, f)
	return nil
}

// AddDiagnostic attempts to record a diagnostic. It enforces sample caps while
// continuing to track accurate aggregate counts.
func (c *Collector) AddDiagnostic(d Diagnostic) {
	// Validate ReasonCode
	switch d.Code {
	case ReasonUserCancelled, ReasonDeadlineExceeded, ReasonInvalidRoot,
		ReasonEligibleReadFailure, ReasonBudgetExhaustion, ReasonGitTimeout, ReasonGitFailure,
		ReasonCheckFailure, ReasonTraversalFailure:
		// Valid code
	default:
		// Normalize to check_failure if unknown to prevent unbounded map growth
		d.Code = ReasonCheckFailure
	}

	if c.reasonCounts[d.Code] < maxInt {
		c.reasonCounts[d.Code]++
	}

	if c.diagTotal >= c.limits.MaxDiagnosticSamples || c.diagExamples[d.Code] >= c.limits.MaxExamplesPerReason {
		if c.diagOmitted < maxInt {
			c.diagOmitted++
		}
		return
	}

	// Payload limits for diagnostic fields
	path := d.Path
	if len(path) > c.limits.MaxDiagnosticPath {
		path = path[:c.limits.MaxDiagnosticPath]
	}
	msg := d.SafeMessage
	if len(msg) > c.limits.MaxSafeMessage {
		msg = msg[:c.limits.MaxSafeMessage]
	}
	d.Path = path
	d.SafeMessage = msg

	c.diagnostics = append(c.diagnostics, d)
	c.diagTotal++
	c.diagExamples[d.Code]++
}

// Findings returns the retained findings.
func (c *Collector) Findings() []finding.Finding {
	return c.findings
}

// Diagnostics returns the retained diagnostic samples.
func (c *Collector) Diagnostics() []Diagnostic {
	return c.diagnostics
}

// AttemptedReturns the number of finding emissions attempted.
func (c *Collector) Attempted() int {
	return c.attempted
}

// AttemptedLowerBound returns whether the Attempted count is a lower bound.
func (c *Collector) AttemptedLowerBound() bool {
	return c.attemptedLowerBound
}

// ExhaustedReturns whether a finding was rejected due to budget limits.
func (c *Collector) Exhausted() bool {
	return c.exhausted
}

// HighestObservedSecurity returns the highest security severity observed and true if any security finding was observed.
func (c *Collector) HighestObservedSecurity() (finding.Severity, bool) {
	return c.highestObservedSecurity, c.hasObservedSecurity
}

// ReasonCounts returns the aggregate counts for each reason code.
func (c *Collector) ReasonCounts() map[ReasonCode]int {
	return c.reasonCounts
}

// DiagnosticOmitted returns the number of diagnostic samples omitted.
func (c *Collector) DiagnosticOmitted() int {
	return c.diagOmitted
}
