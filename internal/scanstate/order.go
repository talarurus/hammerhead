package scanstate

import (
	"cmp"
	"slices"
	"sort"
	"strings"
)

// CompareDiagnostic uses code, stage, rule, slash path, message and raw path.
// Code first makes the per-reason and global sample limits compose: retaining
// the smallest samples never requires keeping an unbounded candidate set.
func CompareDiagnostic(a, b Diagnostic) int {
	if n := cmp.Compare(a.Code, b.Code); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Stage, b.Stage); n != 0 {
		return n
	}
	if n := cmp.Compare(a.RuleID, b.RuleID); n != 0 {
		return n
	}
	if n := cmp.Compare(strings.ReplaceAll(a.Path, "\\", "/"), strings.ReplaceAll(b.Path, "\\", "/")); n != 0 {
		return n
	}
	if n := cmp.Compare(a.SafeMessage, b.SafeMessage); n != 0 {
		return n
	}
	return cmp.Compare(a.Path, b.Path)
}

// RetainExample keeps the lexicographically smallest bounded multiset of
// examples. It retains duplicates and allocates only within the existing cap.
func RetainExample(examples []string, example string, limit int) []string {
	if limit <= 0 {
		return examples
	}
	i := sort.SearchStrings(examples, example)
	if len(examples) < limit {
		examples = append(examples, "")
	} else if i == len(examples) {
		return examples
	}
	copy(examples[i+1:], examples[i:len(examples)-1])
	examples[i] = example
	return examples
}

func compareReason(a, b Reason) int {
	if n := cmp.Compare(a.Code, b.Code); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Count, b.Count); n != 0 {
		return n
	}
	if a.CountIsLowerBound != b.CountIsLowerBound {
		if a.CountIsLowerBound {
			return 1
		}
		return -1
	}
	return slices.Compare(a.Examples, b.Examples)
}

// SortCoverage orders bounded report collections without changing their data.
// Engine registries guarantee unique rule IDs for check coverage entries.
func SortCoverage(c *Coverage) {
	for i := range c.Reasons {
		slices.Sort(c.Reasons[i].Examples)
	}
	slices.SortFunc(c.Reasons, compareReason)
	for i := range c.Checks {
		for j := range c.Checks[i].ReasonCounts {
			slices.Sort(c.Checks[i].ReasonCounts[j].Examples)
		}
		slices.SortFunc(c.Checks[i].ReasonCounts, compareReason)
	}
	slices.SortFunc(c.Checks, func(a, b CheckCoverage) int { return cmp.Compare(a.RuleID, b.RuleID) })
	slices.Sort(c.Policy.Exclusions)
}
