package check

import (
	"context"
	myfs "github.com/ammaarrehman/hammerhead/internal/fs"

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

func (c *RepoHygieneCheck) Run(ctx context.Context, sc *ScanContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Do not increment file inspection counters for presence facts

	hasREADME := myfs.PresenceUnknown
	hasLICENSE := myfs.PresenceUnknown

	if sc.Inventory != nil {
		hasREADME = sc.Inventory.RootREADME
		hasLICENSE = sc.Inventory.RootLICENSE
	}

	if hasREADME == myfs.PresenceAbsent {
		err := sc.Emit(finding.Finding{
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
		if err != nil {
			return err
		}
	}

	if hasLICENSE == myfs.PresenceAbsent {
		err := sc.Emit(finding.Finding{
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
		if err != nil {
			return err
		}
	}

	return nil
}
