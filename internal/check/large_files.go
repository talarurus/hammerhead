package check

import (
	"context"
	"fmt"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

const (
	largeFileCheckID      = "FILE-002"
	largeFileCheckName    = "large-file-detection"
	largeFileCheckVersion = "0.1.0"

	// DefaultLargeFileThreshold is 50 MB (Git warns at 50 MB and hard-blocks at 100 MB on GitHub).
	DefaultLargeFileThreshold int64 = 50 * 1024 * 1024
)

// LargeFileCheck detects files exceeding a configurable size threshold.
//
// Committing large files to Git bloats repository history, degrades clone/fetch
// performance, and frequently indicates accidentally committed datasets,
// media files, or build artifacts.
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
		Description: "Detects repository files exceeding size thresholds to prevent repository bloat and accidental asset commits",
		Version:     largeFileCheckVersion,
	}
}

func (c *LargeFileCheck) Run(_ context.Context, sc *ScanContext) ([]finding.Finding, error) {
	threshold := DefaultLargeFileThreshold
	if sc.Options.LargeFileThresholdBytes > 0 {
		threshold = sc.Options.LargeFileThresholdBytes
	}
	thresholdMB := float64(threshold) / (1024 * 1024)

	var findings []finding.Finding

	for _, file := range sc.Files {
		if file.IsDir {
			continue
		}

		if file.Size > threshold {
			fileSizeMB := float64(file.Size) / (1024 * 1024)
			evidence := fmt.Sprintf("Size: %.2f MB (threshold: %.0f MB)", fileSizeMB, thresholdMB)

			findings = append(findings, finding.Finding{
				ID:          finding.GenerateID(largeFileCheckID, file.Path),
				RuleID:      largeFileCheckID,
				Class:       finding.ClassHygiene,
				Category:    finding.CategoryFiles,
				Severity:    finding.SeverityLow,
				Confidence:  finding.ConfidenceHigh,
				Title:       "Large file committed to repository",
				Description: fmt.Sprintf("A file of %.2f MB was found. Large files bloat Git history, increase clone times, and often indicate accidentally committed binaries, datasets, or build artifacts.", fileSizeMB),
				Remediation: "Remove the file from Git history using git-filter-repo or BFG Repo-Cleaner, add the file or pattern to .gitignore, and consider using Git LFS or external object storage.",
				Path:        file.Path,
				Evidence:    evidence,
				Source:      "hammerhead",
				CheckVer:    largeFileCheckVersion,
			})
		}
	}

	return findings, nil
}
