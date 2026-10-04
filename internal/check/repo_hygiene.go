package check

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

const (
	repoHygieneCheckID      = "PROJ-001"
	repoHygieneCheckName    = "documentation-and-license"
	repoHygieneCheckVersion = "0.1.0"
)

// RepoHygieneCheck inspects the repository root for basic project governance
// and documentation files (README and LICENSE).
//
// These observations are classified under CategoryProject at SeverityLow.
// They reflect repository hygiene and open-source completeness rather than
// security vulnerabilities.
type RepoHygieneCheck struct{}

func (c *RepoHygieneCheck) Meta() Meta {
	return Meta{
		ID:          repoHygieneCheckID,
		Name:        repoHygieneCheckName,
		Category:    finding.CategoryProject,
		Description: "Checks for the presence of essential project governance files (README and LICENSE)",
		Version:     repoHygieneCheckVersion,
	}
}

func (c *RepoHygieneCheck) Run(_ context.Context, sc *ScanContext) ([]finding.Finding, error) {
	hasREADME := false
	hasLICENSE := false

	for _, file := range sc.Files {
		if file.IsDir {
			continue
		}

		// Only check top-level files (no directory separator in relative path)
		if filepath.Dir(file.Path) != "." {
			continue
		}

		baseLower := strings.ToLower(file.Path)

		// README checks
		if isREADME(baseLower) {
			hasREADME = true
		}

		// LICENSE checks
		if isLICENSE(baseLower) {
			hasLICENSE = true
		}
	}

	var findings []finding.Finding

	if !hasREADME {
		findings = append(findings, finding.Finding{
			ID:          finding.GenerateID(repoHygieneCheckID, "README"),
			RuleID:      repoHygieneCheckID,
			Class:       finding.ClassHygiene,
			Category:    finding.CategoryProject,
			Severity:    finding.SeverityLow,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Missing project README",
			Description: "No README file was found in the repository root. A README communicates project purpose, installation instructions, usage, and security disclosure guidelines to developers and auditors.",
			Remediation: "Create a README.md file in the repository root documenting the project's purpose, prerequisites, and instructions.",
			Path:        "README.md",
			Evidence:    "File not found in root directory",
			Source:      "hammerhead",
			CheckVer:    repoHygieneCheckVersion,
		})
	}

	if !hasLICENSE {
		findings = append(findings, finding.Finding{
			ID:          finding.GenerateID(repoHygieneCheckID, "LICENSE"),
			RuleID:      repoHygieneCheckID,
			Class:       finding.ClassHygiene,
			Category:    finding.CategoryProject,
			Severity:    finding.SeverityLow,
			Confidence:  finding.ConfidenceHigh,
			Title:       "Missing project LICENSE",
			Description: "No software license file was found in the repository root. Without an explicit license file, users and contributors have no legal certainty regarding permission to use, distribute, or modify the software.",
			Remediation: "Add a LICENSE file (such as Apache-2.0 or MIT) to the repository root defining clear usage and distribution rights.",
			Path:        "LICENSE",
			Evidence:    "File not found in root directory",
			Source:      "hammerhead",
			CheckVer:    repoHygieneCheckVersion,
		})
	}

	return findings, nil
}

func isREADME(name string) bool {
	switch name {
	case "readme", "readme.md", "readme.markdown", "readme.rst", "readme.txt":
		return true
	}
	return false
}

func isLICENSE(name string) bool {
	switch name {
	case "license", "license.md", "license.txt", "licence", "licence.md", "copying", "copying.md":
		return true
	}
	return false
}
