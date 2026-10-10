package finding_test

import (
	"encoding/json"
	"math/rand"
	"slices"
	"sort"
	"testing"

	"github.com/talarurus/hammerhead/internal/finding"
)

func TestFindingOrder_TotalTieBreaks(t *testing.T) {
	base := finding.Finding{ID: "same-id", RuleID: "R", Class: finding.ClassSecurity,
		Category: finding.CategoryFiles, Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium, Title: "title", Path: "a/b", Line: 2,
		Description: "desc", Remediation: "fix", Evidence: "redacted", Source: "hammerhead", CheckVer: "1"}
	// Each pair also changes a lower-priority key in the opposite direction.
	// These expectations establish precedence independently of the comparator.
	cases := []struct {
		name   string
		change func(*finding.Finding)
	}{
		{"severity-before-class", func(f *finding.Finding) { f.Severity = finding.SeverityCritical; f.Class = finding.ClassInfo }},
		{"class", func(f *finding.Finding) { f.Class = finding.ClassHygiene; f.RuleID = "A" }},
		{"rule", func(f *finding.Finding) { f.RuleID = "S"; f.Path = "0" }},
		{"slash-path", func(f *finding.Finding) { f.Path = "a\\c"; f.Line = 1 }},
		{"numeric-line", func(f *finding.Finding) { f.Line = 10; f.ID = "0" }},
		{"id", func(f *finding.Finding) { f.ID = "z"; f.Title = "0" }},
		{"title", func(f *finding.Finding) { f.Title = "z"; f.Category = finding.CategoryConfig }},
		{"category", func(f *finding.Finding) { f.Category = finding.CategoryGit }},
		{"confidence", func(f *finding.Finding) { f.Confidence = finding.ConfidenceHigh }},
		{"description", func(f *finding.Finding) { f.Description = "z" }},
		{"remediation", func(f *finding.Finding) { f.Remediation = "z" }},
		{"evidence", func(f *finding.Finding) { f.Evidence = "z" }},
		{"source", func(f *finding.Finding) { f.Source = "z" }},
		{"check-version", func(f *finding.Finding) { f.CheckVer = "2" }},
		{"raw-path", func(f *finding.Finding) { f.Path = "a\\b" }},
	}
	inputs := []finding.Finding{base, base} // Identical records and IDs survive.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			tc.change(&other)
			want := -1
			if tc.name == "severity-before-class" {
				want = 1
			}
			if n := finding.CompareCanonical(base, other); n*want <= 0 {
				t.Fatalf("comparison = %d, want sign %d", n, want)
			}
			if n := finding.CompareCanonical(other, base); n*want >= 0 {
				t.Fatalf("reverse comparison = %d", n)
			}
		})
		other := base
		tc.change(&other)
		inputs = append(inputs, other)
	}
	for _, class := range []finding.FindingClass{finding.ClassInfo, "unknown-z", "unknown-a"} {
		other := base
		other.Class = class
		inputs = append(inputs, other)
	}
	want := slices.Clone(inputs)
	sort.Sort(finding.BySeverity(want))
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(9))
	for run := 0; run < 100; run++ {
		got := slices.Clone(inputs)
		rng.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
		sort.Sort(finding.BySeverity(got))
		actual, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(encoded) || len(got) != len(inputs) {
			t.Fatalf("shuffle %d changed serialized order or retained count", run)
		}
	}
	for _, a := range inputs {
		if finding.CompareCanonical(a, a) != 0 {
			t.Fatal("comparison is not reflexive")
		}
		for _, b := range inputs {
			for _, c := range inputs {
				if finding.CompareCanonical(a, b) < 0 && finding.CompareCanonical(b, c) < 0 && finding.CompareCanonical(a, c) >= 0 {
					t.Fatal("comparison is not transitive")
				}
			}
		}
	}
}
