package check_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/finding"
	myfs "github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// TestChecks_CancelDuringLoop verifies that all checks respect context cancellation
// and propagate it immediately.
func TestChecks_CancelDuringLoop(t *testing.T) {
	checks := []struct {
		name string
		chk  check.Check
	}{
		{"GitignoreCheck", &check.GitignoreCheck{}},
		{"LargeFileCheck", &check.LargeFileCheck{}},
		{"ProjectDetectCheck", &check.ProjectDetectCheck{}},
		{"RepoHygieneCheck", &check.RepoHygieneCheck{}},
		{"SecretPatternCheck", &check.SecretPatternCheck{}},
		{"SensitiveFileCheck", &check.SensitiveFileCheck{}},
	}

	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // Cancel immediately before run

			sc := &check.ScanContext{
				RepoRoot: "/dummy",
				Files: []check.FileInfo{
					{Path: "test1.txt"},
					{Path: "test2.txt"},
				},
				Inventory: &myfs.Inventory{},
				ReadFile: func(relPath string, maxSize int64) myfs.ReadOutcome {
					return myfs.ReadOutcome{Status: myfs.ReadStatusText, Data: []byte("dummy content")}
				},
				Emit: func(f finding.Finding) error {
					return nil
				},
				Coverage: &check.Coverage{},
			}

			err := tc.chk.Run(ctx, sc)
			if err == nil {
				t.Fatalf("expected error on canceled context, got nil for %s", tc.name)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled error, got: %v", err)
			}
		})
	}
}

// TestSecrets_ReadErrorMakesPartial verifies that an eligible read error does not
// suppress the check but marks it partial via Coverage.Reasons.
// TestSecrets_ReadErrorMakesPartial verifies that eligible read errors
// do not suppress the check, that previously emitted findings survive,
// and that many read failures aggregate to a bounded reason code.
func TestSecrets_ReadErrorMakesPartial(t *testing.T) {
	ctx := context.Background()
	chk := &check.SecretPatternCheck{}

	cov := &check.Coverage{}

	files := []check.FileInfo{
		{Path: "good.txt"},
	}
	for i := 0; i < 20; i++ {
		files = append(files, check.FileInfo{Path: "bad" + strings.Repeat("a", i) + ".txt"})
	}

	emitted := 0
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files:    files,
		ReadFile: func(relPath string, maxSize int64) myfs.ReadOutcome {
			if strings.HasPrefix(relPath, "bad") {
				return myfs.ReadOutcome{Status: myfs.ReadStatusError, Err: errors.New("io error")}
			}
			return myfs.ReadOutcome{Status: myfs.ReadStatusText, Data: []byte("-----BEGIN PRIVATE KEY-----\nfake")}
		},
		Options:  check.CheckOptions{MaxExamplesPerReason: 5},
		Coverage: cov,
		Emit: func(f finding.Finding) error {
			emitted++
			return nil
		},
	}

	err := chk.Run(ctx, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if emitted != 1 {
		t.Errorf("expected 1 finding emitted, got %d", emitted)
	}
	if cov.EligibleFiles != 21 {
		t.Errorf("expected 21 eligible files, got %d", cov.EligibleFiles)
	}
	if cov.InspectedFiles != 1 {
		t.Errorf("expected 1 inspected file, got %d", cov.InspectedFiles)
	}

	if len(cov.Reasons) != 1 {
		t.Fatalf("expected 1 failure reason, got %d", len(cov.Reasons))
	}
	if cov.Reasons[0].Code != scanstate.ReasonEligibleReadFailure {
		t.Errorf("expected ReasonEligibleReadFailure, got %s", cov.Reasons[0].Code)
	}
	if cov.Reasons[0].Count != 20 {
		t.Errorf("expected 20 failure counts, got %d", cov.Reasons[0].Count)
	}
	if len(cov.Reasons[0].Examples) != 5 { // Bounded to 5
		t.Errorf("expected 5 bounded examples, got %d", len(cov.Reasons[0].Examples))
	}
}

// TestGitignore_LongLineError verifies that bufio.Scanner failure creates a partial coverage reason.
func TestGitignore_LongLineError(t *testing.T) {
	ctx := context.Background()
	chk := &check.GitignoreCheck{}

	// Construct a line > 64KB to trigger bufio.Scanner error
	longLine := strings.Repeat("a", 70000)

	cov := &check.Coverage{}
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Inventory: &myfs.Inventory{
			RootGitignore: myfs.PresencePresent,
		},
		ReadFile: func(relPath string, maxSize int64) myfs.ReadOutcome {
			return myfs.ReadOutcome{Status: myfs.ReadStatusText, Data: []byte(longLine)}
		},
		Options:  check.CheckOptions{MaxExamplesPerReason: 5},
		Coverage: cov,
		Emit: func(f finding.Finding) error {
			t.Errorf("unexpected emit")
			return nil
		},
	}

	err := chk.Run(ctx, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cov.Reasons) != 1 {
		t.Fatalf("expected 1 failure reason, got %d", len(cov.Reasons))
	}
	if cov.Reasons[0].Code != scanstate.ReasonEligibleReadFailure {
		t.Errorf("expected ReasonEligibleReadFailure, got %s", cov.Reasons[0].Code)
	}
	if !strings.Contains(cov.Reasons[0].Examples[0], "parsing error") {
		t.Errorf("expected parsing error example, got %s", cov.Reasons[0].Examples[0])
	}
}

// TestGitignore_ExcludedIsNotMissing verifies that an explicitly excluded .gitignore
// does not trigger a "missing" finding.
func TestGitignore_ExcludedIsNotMissing(t *testing.T) {
	ctx := context.Background()
	chk := &check.GitignoreCheck{}

	cov := &check.Coverage{}
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Inventory: &myfs.Inventory{
			RootGitignore: myfs.PresenceUnknown,
		},
		Options:  check.CheckOptions{MaxExamplesPerReason: 5},
		Coverage: cov,
		Emit: func(f finding.Finding) error {
			t.Errorf("unexpected emit for UNKNOWN presence: %v", f)
			return nil
		},
	}

	err := chk.Run(ctx, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRepoHygiene_IncompleteRootIsNotMissing verifies UNKNOWN roots skip findings.
func TestRepoHygiene_IncompleteRootIsNotMissing(t *testing.T) {
	ctx := context.Background()
	chk := &check.RepoHygieneCheck{}

	cov := &check.Coverage{}
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Inventory: &myfs.Inventory{
			RootREADME:  myfs.PresenceUnknown,
			RootLICENSE: myfs.PresenceUnknown,
		},
		Options:  check.CheckOptions{MaxExamplesPerReason: 5},
		Coverage: cov,
		Emit: func(f finding.Finding) error {
			t.Errorf("unexpected emit for UNKNOWN presence: %v", f)
			return nil
		},
	}

	err := chk.Run(ctx, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestChecks_CancelMidRun verifies cancellation after at least one file is processed
// and that previously emitted findings survive.
func TestChecks_CancelMidRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chk := &check.SecretPatternCheck{}

	emitted := 0
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "test1.txt"},
			{Path: "test2.txt"},
			{Path: "test3.txt"},
		},
		ReadFile: func(relPath string, maxSize int64) myfs.ReadOutcome {
			if relPath == "test2.txt" {
				cancel()
			}
			return myfs.ReadOutcome{
				Status:    myfs.ReadStatusText,
				Data:      []byte("-----BEGIN PRIVATE KEY-----\nfake"),
				BytesRead: 100,
			}
		},
		Emit: func(f finding.Finding) error {
			emitted++
			return nil
		},
		Coverage: &check.Coverage{},
	}

	err := chk.Run(ctx, sc)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if emitted < 1 {
		t.Errorf("expected at least 1 finding emitted before cancel, got %d", emitted)
	}
	if sc.Coverage.InspectedFiles > 2 {
		t.Errorf("expected check to stop inspecting files, got %d inspected", sc.Coverage.InspectedFiles)
	}
}

// TestSecrets_SizeEligibilityBoundary verifies SEC-001 counts eligible files
// correctly relative to the 5 MiB boundary.
func TestSecrets_SizeEligibilityBoundary(t *testing.T) {
	ctx := context.Background()
	chk := &check.SecretPatternCheck{}

	cov := &check.Coverage{}
	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files: []check.FileInfo{
			{Path: "exact_5mb.txt", Size: 5 * 1024 * 1024},
			{Path: "over_5mb.txt", Size: 5*1024*1024 + 1},
			{Path: "small.txt", Size: 100},
		},
		ReadFile: func(relPath string, maxSize int64) myfs.ReadOutcome {
			return myfs.ReadOutcome{
				Status:    myfs.ReadStatusText,
				Data:      []byte("fake"),
				BytesRead: 4,
			}
		},
		Coverage: cov,
		Options:  check.CheckOptions{MaxExamplesPerReason: 5},
		Emit: func(f finding.Finding) error {
			return nil
		},
	}

	err := chk.Run(ctx, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// small and exact_5mb should be eligible. over_5mb should be excluded.
	if cov.EligibleFiles != 2 {
		t.Errorf("expected 2 eligible files, got %d", cov.EligibleFiles)
	}
}
