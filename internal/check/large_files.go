package check

import (
	"context"
	"fmt"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

const (
	largeFileCheckID      = "FILE-002"
	largeFileCheckName    = "large-file-detection"
	largeFileCheckVersion = "0.2.0"

	// DefaultLargeFileThreshold is 50 MB (Git warns at 50 MB and hard-blocks at 100 MB on GitHub).
	DefaultLargeFileThreshold int64 = 50 * 1024 * 1024
)

// LargeFileCheck detects files exceeding a configurable size threshold.
//
// A size observation does not establish whether a file is tracked, committed,
// pushed, or included in repository history.
//
// This check is deterministic and memory-safe: it inspects FileInfo.Size
// recorded during traversal and never reads file contents into memory.
type LargeFileCheck struct {
}

func (c *LargeFileCheck) Meta() Meta {
	return Meta{
		ID:          largeFileCheckID,
		Name:        largeFileCheckName,
		Category:    finding.CategoryFiles,
		Description: "Detects files in the audited directory exceeding the configured size threshold",
		Version:     largeFileCheckVersion,
	}
}

func (c *LargeFileCheck) Run(ctx context.Context, sc *ScanContext) error {
	threshold := DefaultLargeFileThreshold
	if sc.Options.LargeFileThresholdBytes > 0 {
		threshold = sc.Options.LargeFileThresholdBytes
	}
	thresholdMB := float64(threshold) / (1024 * 1024)

	for _, file := range sc.Files {
		if err := ctx.Err(); err != nil {
			return err
		}

		if file.IsDir {
			continue
		}

		if sc.Coverage != nil {
			sc.Coverage.EligibleFiles++
			sc.Coverage.InspectedFiles++
		}

		if file.Size > threshold {
			fileSizeMB := float64(file.Size) / (1024 * 1024)
			evidence := fmt.Sprintf("Size: %.2f MB (threshold: %.0f MB)", fileSizeMB, thresholdMB)

			err := sc.Emit(finding.Finding{
				ID:          finding.GenerateID(largeFileCheckID, file.Path),
				RuleID:      largeFileCheckID,
				Class:       finding.ClassHygiene,
				Category:    finding.CategoryFiles,
				Severity:    finding.SeverityLow,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Large file in audited directory",
				Description: fmt.Sprintf("A file of %.2f MB was found in the audited directory, exceeding the configured size threshold. This size observation does not establish whether the file is tracked, committed, pushed, or included in repository history.", fileSizeMB),
				Remediation: "Review whether the file belongs in version control. If it should remain local, add an appropriate ignore pattern and separately review any existing tracking. If it must be shared, consider Git LFS or external object storage.",
				Path:        file.Path,
				Evidence:    evidence,
				Source:      "hammerhead",
				CheckVer:    largeFileCheckVersion,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}
