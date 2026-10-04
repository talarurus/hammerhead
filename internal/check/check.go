// Package check defines the Check interface and supporting types.
//
// Every security or hygiene check in Hammerhead implements the Check interface.
// Checks receive a ScanContext that provides controlled, safe access to
// repository data. Checks must never access the filesystem directly.
package check

import (
	"context"
	"io/fs"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

// Check is the interface every security check implements.
type Check interface {
	// Meta returns static metadata about this check.
	Meta() Meta

	// Run executes the check and returns any findings.
	// Checks must respect ctx cancellation and should return promptly.
	Run(ctx context.Context, sc *ScanContext) ([]finding.Finding, error)
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

// GitInfo holds basic Git repository metadata available to checks.
type GitInfo struct {
	IsRepo bool   // Whether the target is a Git repository
	Root   string // Repository root path
	Branch string // Current branch name
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
	// Symlinks have been resolved and validated. Excluded directories
	// have been skipped. Binary files are included but flagged.
	Files []FileInfo

	// Git holds repository metadata, or nil for non-Git directories.
	Git *GitInfo

	// ReadFile reads a file's contents by relative path.
	// It enforces size limits and returns an error for files exceeding
	// the configured maximum. Callers should handle errors gracefully.
	ReadFile func(relPath string) ([]byte, error)
}
