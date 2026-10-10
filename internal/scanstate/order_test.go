package scanstate_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func TestDiagnosticOrder_Deterministic(t *testing.T) {
	var input []scanstate.Diagnostic
	for _, code := range []scanstate.ReasonCode{scanstate.ReasonCheckFailure, scanstate.ReasonGitFailure, scanstate.ReasonTraversalFailure} {
		for i := 9; i >= 0; i-- {
			input = append(input, scanstate.Diagnostic{Code: code, Stage: "check", RuleID: fmt.Sprintf("R%d", i%2), Path: fmt.Sprintf("p/%02d", i), SafeMessage: "safe"})
		}
	}
	input = append(input, input[0]) // Duplicate samples still count and remain eligible.
	input = append(input, scanstate.Diagnostic{Code: "unknown", Stage: "z", Path: strings.Repeat("x", 40), SafeMessage: strings.Repeat("m", 40)})
	rng := rand.New(rand.NewSource(9))
	for _, caps := range []struct{ total, perReason int }{{0, 2}, {4, 0}, {1, 1}, {4, 2}, {20, 2}, {200, 5}} {
		t.Run(fmt.Sprintf("total=%d/per-reason=%d", caps.total, caps.perReason), func(t *testing.T) {
			limits := scanstate.ProductionLimits()
			limits.MaxDiagnosticSamples = caps.total
			limits.MaxExamplesPerReason = caps.perReason
			limits.MaxDiagnosticPath = 16
			limits.MaxSafeMessage = 16
			// Offline expected selection is an oracle over the small test fixture;
			// production retains only the capped set while processing each event.
			ordered := slices.Clone(input)
			for i := range ordered {
				if ordered[i].Code == "unknown" {
					ordered[i].Code = scanstate.ReasonCheckFailure
				}
				if len(ordered[i].Path) > 16 {
					ordered[i].Path = ordered[i].Path[:16]
				}
				if len(ordered[i].SafeMessage) > 16 {
					ordered[i].SafeMessage = ordered[i].SafeMessage[:16]
				}
			}
			slices.SortFunc(ordered, scanstate.CompareDiagnostic)
			var want []scanstate.Diagnostic
			counts := map[scanstate.ReasonCode]int{}
			for _, d := range ordered {
				if len(want) < caps.total && counts[d.Code] < caps.perReason {
					want = append(want, d)
					counts[d.Code]++
				}
			}
			for run := 0; run < 100; run++ {
				shuffled := slices.Clone(input)
				rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
				collector := scanstate.NewCollector(limits)
				for _, d := range shuffled {
					collector.AddDiagnostic(d)
					if len(collector.Diagnostics()) > caps.total {
						t.Fatal("sample cap exceeded during ingestion")
					}
					seen := map[scanstate.ReasonCode]int{}
					for _, sample := range collector.Diagnostics() {
						seen[sample.Code]++
						if seen[sample.Code] > caps.perReason {
							t.Fatal("per-reason cap exceeded during ingestion")
						}
					}
				}
				if !reflect.DeepEqual(collector.Diagnostics(), want) {
					t.Fatalf("shuffle %d: got %+v; want %+v", run, collector.Diagnostics(), want)
				}
				if collector.DiagnosticOmitted() != len(input)-len(want) {
					t.Fatal("omitted count changed")
				}
				if collector.ReasonCounts()[scanstate.ReasonCheckFailure] != 12 || collector.ReasonCounts()[scanstate.ReasonGitFailure] != 10 || collector.ReasonCounts()[scanstate.ReasonTraversalFailure] != 10 {
					t.Fatalf("aggregate counts changed: %v", collector.ReasonCounts())
				}
				if collector.Exhausted() {
					t.Fatal("diagnostic cap must not mark finding work incomplete")
				}
			}
		})
	}
	t.Run("coverage-examples-and-groups", func(t *testing.T) {
		var wantJSON []byte
		for run := 0; run < 100; run++ {
			shuffled := slices.Clone(input)
			rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			cov := &check.Coverage{}
			for _, d := range shuffled {
				cov.AddReason(d.Code, 2, d.Path)
			}
			reportCov := scanstate.Coverage{Reasons: cov.Reasons, Checks: []scanstate.CheckCoverage{{RuleID: "Z", ReasonCounts: slices.Clone(cov.Reasons)}, {RuleID: "A"}}}
			scanstate.SortCoverage(&reportCov)
			encoded, err := json.Marshal(reportCov)
			if err != nil {
				t.Fatal(err)
			}
			if run == 0 {
				wantJSON = encoded
			} else if string(encoded) != string(wantJSON) {
				t.Fatalf("shuffle %d changed coverage", run)
			}
			for _, r := range cov.Reasons {
				if r.Code == "unknown" {
					continue
				}
				if !reflect.DeepEqual(r.Examples, []string{"p/00", "p/01"}) {
					t.Fatalf("wrong bounded examples: %+v", r)
				}
			}
		}
	})
}
