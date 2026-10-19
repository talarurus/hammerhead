// Package check defines the Check interface and supporting types.
//
// Every security or hygiene check in Hammerhead implements the Check interface.
// Checks receive a ScanContext that provides controlled, safe access to
// repository data. Checks must never access the filesystem directly.
package check

import (
	"context"
	"io/fs"

	"github.com/talarurus/hammerhead/internal/finding"
	myfs "github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

// Check is the interface every security check implements.
type Check interface {
	// Meta returns static metadata about this check.
	Meta() Meta

	// Run executes the check. Findings are reported via sc.Emit.
	// Checks must respect ctx cancellation and should return promptly.
	Run(ctx context.Context, sc *ScanContext) error
}

// Meta holds static metadata about a check.
type Meta struct {
	ID          string           // Unique rule ID, e.g., "FILE-001"
	Name        string           // Human-readable name, e.g., "sensitive-file-detection"
	Category    finding.Category // Finding category this check produces
	Description string           // What this check does
	Version     string           // Check version, e.g., "0.1.0"
}

// FileInfo represents a single file discovered during safe repository traversal.
// Checks iterate over these rather than walking the filesystem directly.
type FileInfo struct {
	Path    string      // Relative to repository root
	AbsPath string      // Absolute resolved path
	Size    int64       // File size in bytes
	Mode    fs.FileMode // File mode/permissions
	IsDir   bool        // True if this is a directory
}

// ScanContext provides checks with safe, pre-validated access to repository data.
//
// The engine constructs this before check execution. Checks must use the
// provided Files slice rather than walking the filesystem, and ReadFile
// rather than os.ReadFile. This ensures all safety invariants (symlink
// resolution, size limits, path validation) are enforced centrally.
type ScanContext struct {
	// RepoRoot is the absolute path to the repository root.
	RepoRoot string

	// Files is the pre-walked, pre-filtered list of repository files.
	// Excluded directories have been skipped. Content eligibility and binary
	// classification are determined by the guarded ReadFile outcome; FileInfo
	// does not carry a binary-content flag.
	Files []FileInfo

	// Inventory provides facts discovered during traversal.
	Inventory *myfs.Inventory

	// ReadFile safely reads a file's content by relative path.
	ReadFile func(relPath string, maxSize int64) myfs.ReadOutcome

	// Emit records a finding discovered by the check.
	// Checks must respect the returned error, stopping production if budgets are exhausted.
	Emit func(f finding.Finding) error

	// Coverage allows the check to report explicit execution metrics.
	// The engine provides a non-nil pointer.
	Coverage *Coverage

	// Options contains immutable per-run check configuration.
	Options CheckOptions
}

// Coverage allows checks to report detailed execution metrics back to the engine.
type Coverage struct {
	EligibleFiles  int
	InspectedFiles int
	ReadBytes      int
	Reasons        []scanstate.Reason
}

// AddReason safely aggregates failure reasons, bounding the number of examples.
func (c *Coverage) AddReason(code scanstate.ReasonCode, maxExamples int, examples ...string) {
	for i, r := range c.Reasons {
		if r.Code == code {
			c.Reasons[i].Count++
			for _, ex := range examples {
				c.Reasons[i].Examples = scanstate.RetainExample(c.Reasons[i].Examples, ex, maxExamples)
			}
			return
		}
	}
	r := scanstate.Reason{
		Code:  code,
		Count: 1,
	}
	for _, ex := range examples {
		r.Examples = scanstate.RetainExample(r.Examples, ex, maxExamples)
	}
	c.Reasons = append(c.Reasons, r)
}

// CheckOptions holds immutable configuration values for checks during a single scan.
type CheckOptions struct {
	// LargeFileThresholdBytes is the file size limit for FILE-002.
	// If 0, the check's default threshold is used.
	LargeFileThresholdBytes int64

	// MaxExamplesPerReason limits the number of bounded path examples.
	MaxExamplesPerReason int
}
