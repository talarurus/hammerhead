package scanstate

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

func TestCollector_FindingLimit(t *testing.T) {
	limits := ProductionLimits()
	limits.MaxFindings = 2

	c := NewCollector(limits)

	for i := 0; i < 3; i++ {
		err := c.Emit(finding.Finding{
			ID:    "TEST-001",
			Class: finding.ClassSecurity,
			Title: "Test finding",
		})
		if i < 2 && err != nil {
			t.Errorf("expected no error for finding %d, got %v", i, err)
		} else if i == 2 && err != ErrBudgetExhausted {
			t.Errorf("expected error for finding %d", i)
		}
	}

	if len(c.Findings()) != 2 {
		t.Errorf("expected 2 retained findings, got %d", len(c.Findings()))
	}
	if c.Attempted() != 3 {
		t.Errorf("expected 3 attempted findings, got %d", c.Attempted())
	}
	if !c.AttemptedLowerBound() {
		t.Errorf("expected attemptedLowerBound to be true")
	}
	if !c.Exhausted() {
		t.Errorf("expected collector to be exhausted")
	}
}

func TestCollector_PayloadLimit(t *testing.T) {
	limits := ProductionLimits()
	limits.MaxFindingTitle = 10

	c := NewCollector(limits)

	err := c.Emit(finding.Finding{
		ID:    "TEST-001",
		Class: finding.ClassSecurity,
		Title: "This title is way too long",
	})

	if err != ErrPayloadTooLarge {
		t.Errorf("expected ErrPayloadTooLarge, got %v", err)
	}
	if len(c.Findings()) != 0 {
		t.Errorf("expected 0 retained findings, got %d", len(c.Findings()))
	}
	if !c.Exhausted() {
		t.Errorf("expected collector to be exhausted")
	}
}

func TestCollector_DiagnosticAggregation(t *testing.T) {
	limits := ProductionLimits()
	limits.MaxDiagnosticSamples = 4
	limits.MaxExamplesPerReason = 2

	c := NewCollector(limits)

	for i := 0; i < 5; i++ {
		c.AddDiagnostic(Diagnostic{
			Stage:       "check",
			Code:        ReasonCheckFailure,
			SafeMessage: "error 1",
		})
	}
	for i := 0; i < 5; i++ {
		c.AddDiagnostic(Diagnostic{
			Stage:       "check",
			Code:        ReasonInvalidRoot,
			SafeMessage: "error 2",
		})
	}

	diags := c.Diagnostics()
	if len(diags) != 4 { // Max total is 4
		t.Errorf("expected 4 retained diagnostics, got %d", len(diags))
	}

	counts := c.ReasonCounts()
	if counts[ReasonCheckFailure] != 5 {
		t.Errorf("expected 5 ReasonCheckFailure counts, got %d", counts[ReasonCheckFailure])
	}
	if counts[ReasonInvalidRoot] != 5 {
		t.Errorf("expected 5 ReasonInvalidRoot counts, got %d", counts[ReasonInvalidRoot])
	}

	if c.DiagnosticOmitted() != 6 {
		t.Errorf("expected 6 omitted diagnostics, got %d", c.DiagnosticOmitted())
	}

	if c.Exhausted() {
		t.Errorf("expected collector not to be exhausted by diagnostics alone")
	}
}

func TestCollector_ThresholdOnRejectedFinding(t *testing.T) {
	limits := ProductionLimits()
	limits.MaxFindings = 2

	c := NewCollector(limits)

	// Below threshold, admitted
	c.Emit(finding.Finding{
		ID:       "TEST-001",
		Class:    finding.ClassSecurity,
		Severity: finding.SeverityLow,
	})
	c.Emit(finding.Finding{
		ID:       "TEST-002",
		Class:    finding.ClassSecurity,
		Severity: finding.SeverityMedium,
	})

	sev, ok := c.HighestObservedSecurity()
	if !ok || sev != finding.SeverityMedium {
		t.Errorf("expected medium severity, got %v (ok=%v)", sev, ok)
	}

	// Above threshold, but rejected
	err := c.Emit(finding.Finding{
		ID:       "TEST-003",
		Class:    finding.ClassSecurity,
		Severity: finding.SeverityCritical,
	})

	if err != ErrBudgetExhausted {
		t.Errorf("expected budget exhausted error, got %v", err)
	}

	sev, ok = c.HighestObservedSecurity()
	if !ok || sev != finding.SeverityCritical {
		t.Errorf("expected critical severity even when finding is rejected, got %v", sev)
	}

	if len(c.Findings()) != 2 {
		t.Errorf("expected 2 retained findings, got %d", len(c.Findings()))
	}
}

func TestCollector_ReasonNormalization(t *testing.T) {
	limits := ProductionLimits()
	c := NewCollector(limits)

	c.AddDiagnostic(Diagnostic{Code: "attacker-1"})
	c.AddDiagnostic(Diagnostic{Code: "attacker-2"})

	counts := c.ReasonCounts()
	if len(counts) != 1 {
		t.Errorf("expected 1 reason code, got %d", len(counts))
	}
	if counts[ReasonCheckFailure] != 2 {
		t.Errorf("expected 2 ReasonCheckFailure counts, got %d", counts[ReasonCheckFailure])
	}
}

func TestCollector_Saturation(t *testing.T) {
	limits := ProductionLimits()
	limits.MaxFindings = maxInt
	c := NewCollector(limits)

	// Simulate maxInt - 1 attempts
	c.attempted = maxInt - 1
	c.Emit(finding.Finding{}) // hits maxInt
	c.Emit(finding.Finding{}) // saturated

	if c.Attempted() != maxInt {
		t.Errorf("expected %d, got %d", maxInt, c.Attempted())
	}
	if !c.AttemptedLowerBound() {
		t.Errorf("expected attemptedLowerBound to be true")
	}

	c.reasonCounts[ReasonCheckFailure] = maxInt - 1
	c.AddDiagnostic(Diagnostic{Code: ReasonCheckFailure}) // hits maxInt
	c.AddDiagnostic(Diagnostic{Code: ReasonCheckFailure}) // saturated

	if c.reasonCounts[ReasonCheckFailure] != maxInt {
		t.Errorf("expected %d, got %d", maxInt, c.reasonCounts[ReasonCheckFailure])
	}

	c.diagOmitted = maxInt - 1
	// force omitting
	limits.MaxDiagnosticSamples = 0
	c.limits = limits
	c.AddDiagnostic(Diagnostic{Code: ReasonCheckFailure})
	c.AddDiagnostic(Diagnostic{Code: ReasonCheckFailure})

	if c.diagOmitted != maxInt {
		t.Errorf("expected %d, got %d", maxInt, c.diagOmitted)
	}
}
