package engine_test

import (
	"context"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

type dummyCheck struct {
	id string
}

func (d *dummyCheck) Meta() check.Meta {
	return check.Meta{
		ID:       d.id,
		Name:     "dummy-" + d.id,
		Category: finding.CategoryFiles,
	}
}

func (d *dummyCheck) Run(_ context.Context, _ *check.ScanContext) ([]finding.Finding, error) {
	return nil, nil
}

func TestRegistry_AddAndAll(t *testing.T) {
	r := engine.NewRegistry()

	if r.Count() != 0 {
		t.Errorf("expected 0 checks, got %d", r.Count())
	}

	c1 := &dummyCheck{id: "CHECK-001"}
	c2 := &dummyCheck{id: "CHECK-002"}

	if err := r.Add(c1); err != nil {
		t.Fatalf("Add(c1) failed: %v", err)
	}
	if err := r.Add(c2); err != nil {
		t.Fatalf("Add(c2) failed: %v", err)
	}

	if r.Count() != 2 {
		t.Errorf("expected 2 checks, got %d", r.Count())
	}

	all := r.All()
	if len(all) != 2 || all[0].Meta().ID != "CHECK-001" || all[1].Meta().ID != "CHECK-002" {
		t.Errorf("registry did not preserve registration order: %+v", all)
	}

	// Duplicate ID rejected
	if err := r.Add(&dummyCheck{id: "CHECK-001"}); err == nil {
		t.Errorf("expected duplicate check ID to fail, got nil")
	}

	// Empty ID rejected
	if err := r.Add(&dummyCheck{id: ""}); err == nil {
		t.Errorf("expected empty check ID to fail, got nil")
	}
}

func TestDefaultRegistry(t *testing.T) {
	r := engine.DefaultRegistry()
	if r.Count() < 1 {
		t.Errorf("DefaultRegistry should contain at least 1 check, got %d", r.Count())
	}

	foundSensitive := false
	for _, c := range r.All() {
		if c.Meta().ID == "FILE-001" {
			foundSensitive = true
		}
	}
	if !foundSensitive {
		t.Errorf("DefaultRegistry does not contain FILE-001")
	}
}
