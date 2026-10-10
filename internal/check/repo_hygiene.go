package check

import (
	"context"
	myfs "github.com/ammaarrehman/hammerhead/internal/fs"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

const (
	repoHygieneCheckID      = "PROJ-001"
	repoHygieneCheckName    = "documentation-and-license"
	repoHygieneCheckVersion = "0.2.0"
)

// RepoHygieneCheck inspects the repository root for basic project governance
// and documentation files (README and LICENSE).
//
// These observations are classified under CategoryProject at SeverityLow.
// They reflect recognized filenames, not document contents or license adequacy.
type RepoHygieneCheck struct{}

func (c *RepoHygieneCheck) Meta() Meta {
	return Meta{
		ID:          repoHygieneCheckID,
		Name:        repoHygieneCheckName,
		Category:    finding.CategoryProject,
		Description: "Checks for recognized README and license filenames at the audited root without evaluating document contents or legal suitability",
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
			Description: "No recognized README filename was found at the audited root. A README can communicate project purpose, installation instructions, usage, and security disclosure guidelines to developers and auditors.",
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
			Description: "No recognized license filename was found at the audited root. License terms may be provided elsewhere. This check does not evaluate license contents, adequacy, or legal suitability, even when a recognized filename is present.",
			Remediation: "Review where the project's license terms are documented and whether they are appropriate for its intended use. If needed, add a root license file with reviewed terms; a filename alone does not establish licensing rights.",
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
