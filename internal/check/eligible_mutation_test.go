package check

import (
	"context"
	"fmt"
	"testing"

	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Classification depends on the typed outcome alone, never on error wording.
func TestA2R2_SecretReadClassification(t *testing.T) {
	for _, status := range []fs.ReadStatus{fs.ReadStatusError, fs.ReadStatusSafetyReject, fs.ReadStatusBinary, fs.ReadStatusTooLarge} {
		for _, retained := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retained=%t", status, retained), func(t *testing.T) {
				coverage := &Coverage{}
				var findings []finding.Finding
				sc := &ScanContext{
					Files:    []FileInfo{{Path: "a.txt"}, {Path: "z.txt"}},
					Coverage: coverage,
					Options:  CheckOptions{MaxExamplesPerReason: 1},
					ReadFile: func(path string, maxSize int64) fs.ReadOutcome {
						if path == "a.txt" {
							data := []byte("ordinary text\n")
							if retained {
								data = []byte("-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n")
							}
							return fs.ReadOutcome{Status: fs.ReadStatusText, Data: data}
						}
						return fs.ReadOutcome{Status: status, Err: fmt.Errorf("SYNTHETIC PRIVATE ERROR TEXT")}
					},
					Emit: func(f finding.Finding) error { findings = append(findings, f); return nil },
				}
				if err := (&SecretPatternCheck{}).Run(context.Background(), sc); err != nil {
					t.Fatal(err)
				}
				want := 0
				if retained {
					want = 1
				}
				if len(findings) != want || coverage.EligibleFiles != 2 || coverage.InspectedFiles != 1 {
					t.Fatalf("findings/coverage lost: findings=%+v coverage=%+v", findings, coverage)
				}
				if status == fs.ReadStatusError {
					if len(coverage.Reasons) != 1 || coverage.Reasons[0].Code != scanstate.ReasonEligibleReadFailure || coverage.Reasons[0].Count != 1 || len(coverage.Reasons[0].Examples) != 1 || coverage.Reasons[0].Examples[0] != "z.txt" {
						t.Fatalf("required read failure hidden: %+v", coverage)
					}
				} else if len(coverage.Reasons) != 0 {
					t.Fatalf("policy skip became incomplete: %+v", coverage)
				}
			})
		}
	}
}
