package engine_test

import (
	"context"
	"errors"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

// Check stub
type mockCheck struct {
	meta     check.Meta
	findings []finding.Finding
	err      error
}

func (m *mockCheck) Meta() check.Meta {
	return m.meta
}

func (m *mockCheck) Run(ctx context.Context, sc *check.ScanContext) ([]finding.Finding, error) {
	return m.findings, m.err
}

func TestEngine_CheckErrorRetainsFindings(t *testing.T) {
	reg := engine.NewRegistry()
	reg.Add(&mockCheck{
		meta: check.Meta{ID: "MOCK-001"},
		findings: []finding.Finding{
			{RuleID: "MOCK-001", Title: "Mock Finding", Severity: finding.SeverityHigh},
		},
		err: errors.New("mock check error"),
	})

	eng := engine.New(reg)
	res, err := eng.Scan(context.Background(), ".", nil)

	// err shouldn't be returned from Scan just because a check failed.
	if err != nil {
		t.Fatalf("Scan() returned unexpected error: %v", err)
	}
	if res.Status != scanstate.StatusPartial {
		t.Errorf("Expected status partial, got %v", res.Status)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Expected 1 finding retained, got %d", len(res.Findings))
	}
}

type sleepCheck struct {
	meta check.Meta
}

func (c *sleepCheck) Meta() check.Meta {
	return c.meta
}

func (c *sleepCheck) Run(ctx context.Context, sc *check.ScanContext) ([]finding.Finding, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(1 * time.Second):
		return nil, nil
	}
}

type cancelTriggerCheck struct {
	meta   check.Meta
	cancel context.CancelFunc
}

func (c *cancelTriggerCheck) Meta() check.Meta { return c.meta }
func (c *cancelTriggerCheck) Run(ctx context.Context, _ *check.ScanContext) ([]finding.Finding, error) {
	// Emit a finding
	f := finding.Finding{RuleID: c.meta.ID, Title: "A finding"}

	// Trigger cancellation
	c.cancel()

	// Return the finding
	return []finding.Finding{f}, nil
}

type verifyCancelledCheck struct {
	meta check.Meta
	run  bool
}

func (c *verifyCancelledCheck) Meta() check.Meta { return c.meta }
func (c *verifyCancelledCheck) Run(ctx context.Context, _ *check.ScanContext) ([]finding.Finding, error) {
	c.run = true
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return nil, nil
}

func TestEngine_CancelRetainsResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := engine.NewRegistry()
	trigger := &cancelTriggerCheck{
		meta:   check.Meta{ID: "CANCEL-001"},
		cancel: cancel,
	}
	verify := &verifyCancelledCheck{
		meta: check.Meta{ID: "LATE-002"},
	}
	reg.Add(trigger)
	reg.Add(verify)

	eng := engine.New(reg)

	res, err := eng.Scan(ctx, ".", nil)
	if res == nil {
		t.Fatalf("Expected non-nil result")
	}
	if err == nil {
		t.Fatalf("Expected cancellation error")
	}
	if res.Status != scanstate.StatusCancelled {
		t.Errorf("Expected status cancelled, got %v", res.Status)
	}
	if len(res.Diagnostics) == 0 || res.Diagnostics[0].Code != scanstate.ReasonUserCancelled {
		t.Errorf("Expected cancellation diagnostic, got %v", res.Diagnostics)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "CANCEL-001" {
		t.Errorf("Expected previous findings to be retained, got %v", res.Findings)
	}
}

func TestEngine_CancelLastCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := engine.NewRegistry()
	trigger := &cancelTriggerCheck{
		meta:   check.Meta{ID: "CANCEL-LAST"},
		cancel: cancel,
	}
	reg.Add(trigger)

	eng := engine.New(reg)

	res, err := eng.Scan(ctx, ".", nil)
	if res == nil {
		t.Fatalf("Expected non-nil result")
	}
	if err == nil {
		t.Fatalf("Expected cancellation error, got nil")
	}
	if res.Status != scanstate.StatusCancelled {
		t.Errorf("Expected status cancelled, got %v", res.Status)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "CANCEL-LAST" {
		t.Errorf("Expected findings to be retained, got %v", res.Findings)
	}
}

type walkAssertCheck struct {
	meta check.Meta
}

func (c *walkAssertCheck) Meta() check.Meta { return c.meta }
func (c *walkAssertCheck) Run(_ context.Context, sc *check.ScanContext) ([]finding.Finding, error) {
	if len(sc.Files) > 0 {
		return []finding.Finding{{RuleID: c.meta.ID, Title: "Walked file found"}}, nil
	}
	return nil, nil
}

func TestEngine_PartialWalkRetained(t *testing.T) {
	reg := engine.NewRegistry()
	reg.Add(&walkAssertCheck{meta: check.Meta{ID: "WALK-001"}})
	eng := engine.New(reg)

	tempDir := t.TempDir()
	for _, f := range []string{"file1.txt", "file2.txt", "file3.txt"} {
		if err := os.WriteFile(filepath.Join(tempDir, f), []byte("content"), 0644); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	config := &engine.ScanConfig{
		Walker: &fs.WalkerConfig{
			MaxFiles: 1,
		},
	}
	res, err := eng.Scan(context.Background(), tempDir, config)

	// err is returned because walk failed, but result must be retained
	if res == nil {
		t.Fatalf("Expected non-nil result")
	}
	if err == nil {
		t.Fatalf("Expected walk error, got nil")
	}
	if res.Status != scanstate.StatusPartial {
		t.Errorf("Expected status partial, got %v", res.Status)
	}
	if len(res.Diagnostics) == 0 || res.Diagnostics[0].Code != scanstate.ReasonBudgetExhaustion {
		t.Errorf("Expected traversal failure diagnostic, got %+v", res.Diagnostics)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "WALK-001" {
		t.Errorf("Expected finding from partial walk, got %v", res.Findings)
	}
}
