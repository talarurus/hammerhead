// Package engine orchestrates security checks against a repository.
//
// The engine constructs a ScanContext from the repository, runs all
// registered checks, collects findings, and returns results. It owns
// the lifecycle of a scan operation.
package engine

import (
	"fmt"

	"github.com/ammaarrehman/hammerhead/internal/check"
)

// Registry holds an explicitly assembled list of security checks.
//
// Checks are added via Add() — there is no init()-based self-registration.
// This makes the set of active checks auditable, deterministic, and
// easy to understand for contributors.
type Registry struct {
	checks []check.Check
	ids    map[string]bool // tracks registered IDs to prevent duplicates
}

// NewRegistry creates an empty check registry.
func NewRegistry() *Registry {
	return &Registry{
		ids: make(map[string]bool),
	}
}

// Add registers a check. Returns an error if a check with the same ID
// is already registered.
func (r *Registry) Add(c check.Check) error {
	meta := c.Meta()
	if meta.ID == "" {
		return fmt.Errorf("check has empty ID")
	}
	if r.ids[meta.ID] {
		return fmt.Errorf("duplicate check ID: %s", meta.ID)
	}
	r.ids[meta.ID] = true
	r.checks = append(r.checks, c)
	return nil
}

// All returns all registered checks in registration order.
func (r *Registry) All() []check.Check {
	result := make([]check.Check, len(r.checks))
	copy(result, r.checks)
	return result
}

// Count returns the number of registered checks.
func (r *Registry) Count() int {
	return len(r.checks)
}

// DefaultRegistry assembles the standard set of V0.1 checks.
// This is the single, explicit place where all checks are registered.
//
// To add a new check:
//  1. Create the check implementation in internal/check/
//  2. Add it to this function
//
// That's it. No init() magic, no reflection, no config files.
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// File checks
	mustAdd(r, &check.SensitiveFileCheck{})
	mustAdd(r, &check.LargeFileCheck{})

	// Git checks
	mustAdd(r, &check.GitignoreCheck{})
	mustAdd(r, &check.GitHealthCheck{})

	// Project checks
	mustAdd(r, &check.RepoHygieneCheck{})
	mustAdd(r, &check.ProjectDetectCheck{})

	// Secret content checks
	mustAdd(r, &check.SecretPatternCheck{})

	return r
}

func mustAdd(r *Registry, c check.Check) {
	if err := r.Add(c); err != nil {
		panic(fmt.Sprintf("registering check %s: %v", c.Meta().ID, err))
	}
}
