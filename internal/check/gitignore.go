package check

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

const (
	gitignoreCheckID      = "GIT-001"
	gitignoreCheckName    = "gitignore-hygiene"
	gitignoreCheckVersion = "0.2.0"
)

// requiredPatternGroup defines a group of sensitive patterns where at least
// one should ideally be present in .gitignore.
type requiredPatternGroup struct {
	categoryName string
	description  string
	patterns     []string // matching any of these satisfies the group
	recommended  string   // pattern to suggest adding
}

var standardHygieneGroups = []requiredPatternGroup{
	{
		categoryName: "Environment files",
		description:  "Environment configurations may contain sensitive values",
		patterns:     []string{".env", "*.env", ".env.*", ".env*", ".env.local"},
		recommended:  ".env",
	},
	{
		categoryName: "Private keys",
		description:  "Files named like private keys may contain sensitive material",
		patterns:     []string{"*.key", "id_rsa", "id_ed25519", "id_*", "*.pkcs12", "*.p12", "*.pfx"},
		recommended:  "*.key, id_rsa, id_ed25519",
	},
}

// GitignoreCheck looks for supported textual patterns in the root .gitignore.
// It does not evaluate Git's effective ignore behavior, including negations,
// nested/global ignore files, or tracking state.
//
// Important design considerations:
//   - A .gitignore entry alone does NOT guarantee a secret is safe; already-tracked
//     files are unaffected by .gitignore.
//   - Remediation explicitly clarifies the need to untrack existing files if present.
type GitignoreCheck struct{}

func (c *GitignoreCheck) Meta() Meta {
	return Meta{
		ID:          gitignoreCheckID,
		Name:        gitignoreCheckName,
		Category:    finding.CategoryGit,
		Description: "Looks for supported textual ignore patterns for environment files and private-key filenames in the root .gitignore",
		Version:     gitignoreCheckVersion,
	}
}

func (c *GitignoreCheck) Run(ctx context.Context, sc *ScanContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	hasGitignore := fs.PresenceUnknown
	if sc.Inventory != nil {
		hasGitignore = sc.Inventory.RootGitignore
	}

	if hasGitignore == fs.PresenceUnknown {
		return nil
	}

	if hasGitignore == fs.PresenceAbsent {
		return sc.Emit(finding.Finding{
			ID:          finding.GenerateID(gitignoreCheckID, ".gitignore"),
			RuleID:      gitignoreCheckID,
			Class:       finding.ClassHygiene,
			Category:    finding.CategoryGit,
			Severity:    finding.SeverityLow,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Missing .gitignore file",
			Description: "No .gitignore file was found at the audited root. Other ignore sources and Git tracking state were not evaluated by this check; this does not establish which files Git ignores.",
			Remediation: "Review the project's ignore policy. If needed, create a root .gitignore with appropriate patterns for local environment files, private-key files, and build artifacts. Verify effective ignore behavior and review already-tracked files separately.",
			Path:        ".gitignore",
			Evidence:    "File not found",
			Source:      "hammerhead",
			CheckVer:    gitignoreCheckVersion,
		})
	}

	if sc.Coverage != nil {
		sc.Coverage.EligibleFiles++
	}

	// 2. Read .gitignore
	outcome := sc.ReadFile(".gitignore", 10*1024*1024)
	if sc.Coverage != nil {
		sc.Coverage.ReadBytes += int(outcome.BytesRead)
	}
	if outcome.Status == fs.ReadStatusBudgetExhaust {
		return scanstate.ErrBudgetExhausted
	}

	if outcome.Status != fs.ReadStatusText {
		if sc.Coverage != nil {
			sc.Coverage.AddReason(scanstate.ReasonEligibleReadFailure, sc.Options.MaxExamplesPerReason, fmt.Sprintf(".gitignore (status: %s)", outcome.Status))
		}
		return nil
	}
	data := outcome.Data

	if sc.Coverage != nil {
		sc.Coverage.InspectedFiles++
	}

	// 3. Evaluate each required pattern group directly from the buffer
	// to avoid unbounded memory allocation for activeEntries.
	matchedGroups := make([]bool, len(standardHygieneGroups))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Safe handling of unusually long lines by using default 64KB max token size.
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for i, group := range standardHygieneGroups {
			if matchedGroups[i] {
				continue
			}
			for _, required := range group.patterns {
				if matchPattern(line, required) {
					matchedGroups[i] = true
					break
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		if sc.Coverage != nil {
			sc.Coverage.AddReason(scanstate.ReasonEligibleReadFailure, sc.Options.MaxExamplesPerReason, ".gitignore (parsing error)")
		}
		// Partial check status when required parsing fails.
		// No misleading missing-pattern findings after an incomplete parse.
		return nil
	}

	for i, group := range standardHygieneGroups {
		if !matchedGroups[i] {
			title := fmt.Sprintf("Supported textual ignore pattern not found: %s", group.categoryName)
			desc := fmt.Sprintf(
				"No supported textual pattern for %s was found in the root .gitignore. %s. This heuristic does not evaluate Git's effective ignore behavior, other ignore sources, negations, or tracking state.",
				strings.ToLower(group.categoryName),
				group.description,
			)
			remedy := fmt.Sprintf(
				"Review whether '%s' suits this project's ignore policy and add appropriate patterns if needed. Verify effective ignore behavior. If a sensitive file is already tracked and should remain local, review untracking it with 'git rm --cached <file>'; ignore patterns alone do not untrack files.",
				group.recommended,
			)

			err := sc.Emit(finding.Finding{
				ID:          finding.GenerateID(gitignoreCheckID, group.categoryName),
				RuleID:      gitignoreCheckID,
				Class:       finding.ClassHygiene,
				Category:    finding.CategoryGit,
				Severity:    finding.SeverityLow,
				Confidence:  finding.ConfidenceHigh,
				Title:       title,
				Description: desc,
				Remediation: remedy,
				Path:        ".gitignore",
				Evidence:    fmt.Sprintf("Supported textual pattern not found for: %s", group.recommended),
				Source:      "hammerhead",
				CheckVer:    gitignoreCheckVersion,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func matchPattern(entry, target string) bool {
	targetClean := strings.TrimPrefix(target, "/")
	entryClean := strings.TrimPrefix(entry, "/")
	if entryClean == targetClean || entry == target {
		return true
	}
	// Suffix match for wildcard extensions like *.key
	if strings.HasPrefix(targetClean, "*.") && strings.HasSuffix(entryClean, targetClean[1:]) {
		return true
	}
	return false
}
