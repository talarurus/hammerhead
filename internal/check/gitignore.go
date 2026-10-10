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
	gitignoreCheckVersion = "0.1.0"
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
		description:  "Environment variable configurations often contain live API tokens, database credentials, and secrets",
		patterns:     []string{".env", "*.env", ".env.*", ".env*", ".env.local"},
		recommended:  ".env",
	},
	{
		categoryName: "Private keys",
		description:  "Cryptographic private keys grant system access and should never be staged",
		patterns:     []string{"*.key", "id_rsa", "id_ed25519", "id_*", "*.pkcs12", "*.p12", "*.pfx"},
		recommended:  "*.key, id_rsa, id_ed25519",
	},
}

// GitignoreCheck inspects the repository's .gitignore file to verify that
// common sensitive file patterns (e.g. .env, private keys) are excluded.
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
		Description: "Checks that .gitignore excludes common sensitive files such as environment configurations and private keys",
		Version:     gitignoreCheckVersion,
	}
}

func (c *GitignoreCheck) Run(_ context.Context, sc *ScanContext) error {
	// 1. Locate root .gitignore
	// The file list check was removed since presence is evaluated through the inventory.

	hasGitignore := fs.PresenceUnknown
	if sc.Inventory != nil {
		hasGitignore = sc.Inventory.RootGitignore
	}

	isMissing := false
	if hasGitignore == fs.PresenceAbsent {
		isMissing = true
	}

	if hasGitignore == fs.PresenceUnknown {
		return nil
	}

	// If no .gitignore exists, report a single finding
	if isMissing {
		return sc.Emit(finding.Finding{
			ID:          finding.GenerateID(gitignoreCheckID, ".gitignore"),
			RuleID:      gitignoreCheckID,
			Class:       finding.ClassHygiene,
			Category:    finding.CategoryGit,
			Severity:    finding.SeverityLow,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Missing .gitignore file",
			Description: "No .gitignore file was found at the repository root. Without a .gitignore file, local environment files, private keys, and build artifacts are at high risk of being inadvertently committed.",
			Remediation: "Create a .gitignore file at the repository root and add standard exclusions for environment files (.env), private keys (*.key, id_rsa), and build artifacts.",
			Path:        ".gitignore",
			Evidence:    "File not found",
			Source:      "hammerhead",
			CheckVer:    gitignoreCheckVersion,
		})
	}

	// 2. Read .gitignore
	outcome := sc.ReadFile(".gitignore", 10*1024*1024)
	if outcome.Status == fs.ReadStatusBudgetExhaust {
		return scanstate.ErrBudgetExhausted
	}
	if outcome.Status != fs.ReadStatusText {
		return fmt.Errorf("reading .gitignore: %w", outcome.Err)
	}
	data := outcome.Data

	// 3. Evaluate each required pattern group directly from the buffer
	// to avoid unbounded memory allocation for activeEntries.
	matchedGroups := make([]bool, len(standardHygieneGroups))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
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

	for i, group := range standardHygieneGroups {
		if !matchedGroups[i] {
			title := fmt.Sprintf("Sensitive pattern missing from .gitignore: %s", group.categoryName)
			desc := fmt.Sprintf(
				"The repository's .gitignore file does not exclude %s (%s). Note: adding patterns to .gitignore only prevents untracked files from being staged; files that are already tracked by Git remain tracked.",
				strings.ToLower(group.categoryName),
				group.description,
			)
			remedy := fmt.Sprintf(
				"Add '%s' to .gitignore. If any such files are already tracked in version control, untrack them using 'git rm --cached <file>' before committing.",
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
				Evidence:    fmt.Sprintf("Missing rule for: %s", group.recommended),
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
