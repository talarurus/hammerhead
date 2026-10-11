package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/app"
	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

type observedCheck struct {
	check.Check
	emissions, reads *int
}

func (c observedCheck) Run(ctx context.Context, sc *check.ScanContext) error {
	emit, read := sc.Emit, sc.ReadFile
	defer func() { sc.Emit, sc.ReadFile = emit, read }()
	sc.Emit = func(f finding.Finding) error { *c.emissions++; return emit(f) }
	sc.ReadFile = func(path string, max int64) fs.ReadOutcome { *c.reads++; return read(path, max) }
	return c.Check.Run(ctx, sc)
}

func TestAcceptance_ProductionStopsAtCaps(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, mode := range []string{"filenames", "matches", "reads"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			registry := engine.NewRegistry()
			emissions, reads := 0, 0
			limits := scanstate.ProductionLimits()
			limits.MaxFindings = 3
			checks := engine.DefaultRegistry().All()
			if mode != "filenames" {
				checks = []check.Check{&check.SecretPatternCheck{}}
			}
			for _, c := range checks {
				if err := registry.Add(observedCheck{c, &emissions, &reads}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "matches" {
				if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte(strings.Repeat("AKIA0000000000000000\n", 1000)), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				for i := 0; i < 10; i++ {
					name := fmt.Sprintf("%02d.txt", i)
					if mode == "filenames" {
						name += ".key"
					}
					if err := os.WriteFile(filepath.Join(root, name), []byte(strings.Repeat("a", 64)), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "reads" {
				limits.MaxAggregateReadBytes = 64
			}
			r, err := engine.New(registry).Scan(context.Background(), root, &engine.ScanConfig{Limits: &limits})
			if err != nil || r.Status != scanstate.StatusPartial || app.ExitCode(r, app.ThresholdPolicy{Disabled: true}) != 2 {
				t.Fatalf("budget did not produce partial/2: %v %+v", err, r)
			}
			switch mode {
			case "filenames":
				if emissions != 4 || reads != 0 || r.ChecksRun != 1 || len(r.Findings) != 3 {
					t.Fatalf("production continued: emits=%d reads=%d checks=%d findings=%d", emissions, reads, r.ChecksRun, len(r.Findings))
				}
			case "matches":
				if emissions != 4 || reads != 1 || r.Attempted() != 4 || len(r.Findings) != 3 {
					t.Fatalf("match production continued: emits=%d reads=%d attempts=%d", emissions, reads, r.Attempted())
				}
			case "reads":
				if reads != 2 || emissions != 0 || r.Coverage.Checks[0].ReadBytes == nil || *r.Coverage.Checks[0].ReadBytes != 64 {
					t.Fatalf("read production continued: reads=%d coverage=%+v", reads, r.Coverage.Checks)
				}
			}
		})
	}
}

func TestAcceptance_EffectivePolicyTelemetry(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	r, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), t.TempDir(), &engine.ScanConfig{ExcludePatterns: []string{"private", "*.min.js"}})
	if err != nil || r.Status != scanstate.StatusCompleted {
		t.Fatal(r, err)
	}
	for key, want := range map[string]int64{
		"max_depth": 50, "max_retained_inventory_entries": 100000, "directory_batch_entries": 256, "max_names_per_directory": 10000, "max_examined_entries": 100000,
		"max_native_read_bytes": 10485760, "sec001_max_eligible_bytes": 5242880, "max_aggregate_native_read_bytes": 268435456, "max_findings_retained": 10000,
		"git_command_timeout_ms": 10000, "max_git_stdout_bytes": 4194304, "max_git_stderr_bytes": 65536, "git_termination_grace_ms": 1000, "git_wait_cleanup_ms": 1000, "symlink_resolution_steps": 40,
	} {
		if got := r.Coverage.Policy.EffectiveLimits[key]; got != want {
			t.Errorf("policy %s=%d want %d", key, got, want)
		}
	}
	for _, pattern := range []string{".git", "node_modules", "private", "*.min.js"} {
		if !slices.Contains(r.Coverage.Policy.Exclusions, pattern) {
			t.Errorf("missing exclusion %q", pattern)
		}
	}
	if !slices.IsSorted(r.Coverage.Policy.Exclusions) || r.Coverage.DiagnosticExamplesOmitted == nil || *r.Coverage.DiagnosticExamplesOmitted != 0 {
		t.Fatal("incomplete policy/known zero telemetry")
	}
	for _, c := range r.Coverage.Checks {
		if c.EligibleFiles == nil || c.InspectedFiles == nil || c.ReadBytes == nil {
			t.Fatalf("uninstrumented check: %+v", c)
		}
	}
}

func TestAcceptance_UnstartedCoverageIsMeasuredZeroWork(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, mode := range []string{"pre-cancel", "invalid-root"} {
		ctx, cancel := context.WithCancel(context.Background())
		root := filepath.Join(t.TempDir(), "missing")
		if mode == "pre-cancel" {
			cancel()
		}
		r, err := engine.New(engine.DefaultRegistry()).Scan(ctx, root, nil)
		cancel()
		if err == nil || r == nil || app.ExitCode(r, app.ThresholdPolicy{Disabled: true}) != 2 {
			t.Fatalf("setup/cancel passed: %+v %v", r, err)
		}
		if r.Coverage.Traversal.ExaminedEntries == nil || *r.Coverage.Traversal.ExaminedEntries != 0 || r.Coverage.Traversal.InventoryComplete == nil || *r.Coverage.Traversal.InventoryComplete {
			t.Fatal("unstarted work fabricated completeness or unknown counters")
		}
		if len(r.Coverage.Checks) != 7 {
			t.Fatalf("lost unstarted check accounting: %+v", r.Coverage)
		}
		for _, c := range r.Coverage.Checks {
			if c.Status != scanstate.CheckStatusNotRun || c.ReadBytes == nil || *c.ReadBytes != 0 {
				t.Fatalf("unstarted check telemetry: %+v", c)
			}
		}
	}
}
