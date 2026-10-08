// Package fs provides safe filesystem traversal for scanning untrusted repositories.
//
// The SafeWalker enforces security invariants:
//   - Symlinks are resolved and rejected if they escape the repository root
//   - Directory depth is bounded to prevent stack exhaustion
//   - File count is bounded to prevent resource exhaustion
//   - Common generated/vendor directories are excluded by default
//   - Malicious filenames (control characters, path traversal) are detected
//   - The .git directory is always excluded
package fs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrBudgetExhausted indicates that traversal exceeded the maximum configured limits.
var ErrBudgetExhausted = errors.New("traversal budget exhausted")

// Defaults for safety limits.
const (
	DefaultMaxDepth    = 50
	DefaultMaxFiles    = 100_000
	DefaultMaxFileSize = 10 * 1024 * 1024 // 10 MB
)

// WalkedFile represents a single file yielded by SafeWalker.
type WalkedFile struct {
	Path    string      // Relative to repository root
	AbsPath string      // Absolute, symlink-resolved path
	Size    int64       // File size in bytes
	Mode    os.FileMode // File permissions
	IsDir   bool        // True if directory
}

// WalkerConfig controls SafeWalker behavior.
type WalkerConfig struct {
	MaxDepth              int      // Maximum directory depth (0 = use default)
	MaxFiles              int      // Maximum number of files to yield (0 = use default)
	MaxFileSize           int64    // Maximum file size in bytes for content reading (0 = use default)
	MaxAggregateReadBytes int64    // Maximum aggregate read bytes (0 = no limit, but typically bounded by scanstate)
	ExtraDirs             []string // Additional directory names to exclude
	ExcludePatterns       []string // Glob/path patterns to exclude (e.g. "testdata/repos/dirty", "*.min.js", "vendor")

	// Bounding limits plumbed from engine/scanstate
	MaxSkippedEntries    int
	MaxExamplesPerReason int
	MaxDiagnosticPath    int
	MaxSafeMessage       int
}

func (c *WalkerConfig) maxDepth() int {
	if c != nil && c.MaxDepth > 0 {
		return c.MaxDepth
	}
	return DefaultMaxDepth
}

func (c *WalkerConfig) maxFiles() int {
	if c != nil && c.MaxFiles > 0 {
		return c.MaxFiles
	}
	return DefaultMaxFiles
}

func (c *WalkerConfig) maxFileSize() int64 {
	if c != nil && c.MaxFileSize > 0 {
		return c.MaxFileSize
	}
	return DefaultMaxFileSize
}

func (c *WalkerConfig) maxAggregateReadBytes() int64 {
	if c != nil && c.MaxAggregateReadBytes > 0 {
		return c.MaxAggregateReadBytes
	}
	return 0 // 0 means unbounded here if not set, but the engine will provide scanstate limits
}

func (c *WalkerConfig) maxSkippedEntries() int {
	if c != nil && c.MaxSkippedEntries > 0 {
		return c.MaxSkippedEntries
	}
	return 200 // default fallback
}

func (c *WalkerConfig) maxExamplesPerReason() int {
	if c != nil && c.MaxExamplesPerReason > 0 {
		return c.MaxExamplesPerReason
	}
	return 5
}

func (c *WalkerConfig) maxDiagnosticPath() int {
	if c != nil && c.MaxDiagnosticPath > 0 {
		return c.MaxDiagnosticPath
	}
	return 16384
}

func (c *WalkerConfig) maxSafeMessage() int {
	if c != nil && c.MaxSafeMessage > 0 {
		return c.MaxSafeMessage
	}
	return 2048
}

// defaultExcludedDirs are directories that are always skipped during traversal.
var defaultExcludedDirs = map[string]bool{
	".git":          true,
	"node_modules":  true,
	"vendor":        true,
	".venv":         true,
	"venv":          true,
	"__pycache__":   true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
	".cache":        true,
	"dist":          true,
	"build":         true,
	".next":         true,
	".nuxt":         true,
	".terraform":    true,
}

type SkipCategory string

const (
	SkipCategoryWalkError        SkipCategory = "walk_error"
	SkipCategoryRelativePathFail SkipCategory = "relative_path_fail"
	SkipCategoryUserExcluded     SkipCategory = "user_excluded"
	SkipCategoryMaliciousName    SkipCategory = "malicious_name"
	SkipCategoryDepthExceeded    SkipCategory = "depth_exceeded"
	SkipCategoryExcludedDir      SkipCategory = "excluded_dir"
	SkipCategorySymlinkFail      SkipCategory = "symlink_fail"
	SkipCategoryPathTraversal    SkipCategory = "path_traversal"
)

// SafeWalker performs bounded, symlink-aware filesystem traversal.
type SafeWalker struct {
	root               string
	config             *WalkerConfig
	excludedDirs       map[string]bool
	aggregateReadBytes int64

	skipped           []SkippedEntry
	skippedTotal      int
	skippedOmitted    int
	skippedCounts     map[SkipCategory]int
	skippedCategories map[SkipCategory]int
}

// SkippedEntry records a file or directory that was skipped during traversal.
type SkippedEntry struct {
	Path     string       // Relative path
	Category SkipCategory // Categorical reason
	Reason   string       // Why it was skipped
}

const maxInt = int(^uint(0) >> 1)

func (w *SafeWalker) addSkipped(path string, cat SkipCategory, reason string) {
	if w.skippedCounts[cat] < maxInt {
		w.skippedCounts[cat]++
	}

	if w.skippedTotal >= w.config.maxSkippedEntries() || w.skippedCategories[cat] >= w.config.maxExamplesPerReason() {
		if w.skippedOmitted < maxInt {
			w.skippedOmitted++
		}
		return
	}

	maxPath := w.config.maxDiagnosticPath()
	if len(path) > maxPath {
		path = path[:maxPath]
	}
	maxReason := w.config.maxSafeMessage()
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}

	w.skipped = append(w.skipped, SkippedEntry{Path: path, Category: cat, Reason: reason})
	w.skippedTotal++
	w.skippedCategories[cat]++
}

// NewSafeWalker creates a walker rooted at the given directory.
// The root path is resolved to its absolute, symlink-free form.
func NewSafeWalker(root string, config *WalkerConfig) (*SafeWalker, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving root path: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("resolving root symlinks: %w", err)
	}

	excluded := make(map[string]bool, len(defaultExcludedDirs))
	for k, v := range defaultExcludedDirs {
		excluded[k] = v
	}
	if config != nil {
		for _, d := range config.ExtraDirs {
			excluded[d] = true
		}
	}

	return &SafeWalker{
		root:              resolvedRoot,
		config:            config,
		excludedDirs:      excluded,
		skippedCounts:     make(map[SkipCategory]int),
		skippedCategories: make(map[SkipCategory]int),
	}, nil
}

// Walk traverses the repository and returns all discovered files.
// It enforces all safety limits and records skipped entries.
func (w *SafeWalker) Walk() ([]WalkedFile, error) {
	var files []WalkedFile
	maxFiles := w.config.maxFiles()
	maxDepth := w.config.maxDepth()

	depthBudgetExceeded := false

	err := filepath.Walk(w.root, func(absPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Permission denied or similar — skip, don't abort.
			relPath, _ := filepath.Rel(w.root, absPath)
			w.addSkipped(relPath, SkipCategoryWalkError, fmt.Sprintf("walk error: %v", walkErr))
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Compute relative path.
		relPath, err := filepath.Rel(w.root, absPath)
		if err != nil {
			w.addSkipped(absPath, SkipCategoryRelativePathFail, "failed to compute relative path")
			return nil
		}

		// Skip the root directory entry itself.
		if relPath == "." {
			return nil
		}

		// Check user-configured exclude patterns.
		if w.IsExcluded(relPath, filepath.Base(relPath)) {
			w.addSkipped(relPath, SkipCategoryUserExcluded, "excluded by user pattern")
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check for malicious filenames.
		if reason := checkFilename(filepath.Base(relPath)); reason != "" {
			w.addSkipped(relPath, SkipCategoryMaliciousName, reason)
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check directory depth.
		depth := strings.Count(relPath, string(filepath.Separator)) + 1
		if depth > maxDepth {
			w.addSkipped(relPath, SkipCategoryDepthExceeded, fmt.Sprintf("exceeded max depth (%d)", maxDepth))
			depthBudgetExceeded = true
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip excluded directories.
		if info.IsDir() {
			baseName := filepath.Base(absPath)
			if w.excludedDirs[baseName] {
				w.addSkipped(relPath, SkipCategoryExcludedDir, "excluded directory")
				return filepath.SkipDir
			}
		}

		// Handle symlinks.
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(absPath)
			if err != nil {
				w.addSkipped(relPath, SkipCategorySymlinkFail, fmt.Sprintf("unresolvable symlink: %v", err))
				return nil
			}
			if !isInsideDir(resolved, w.root) {
				w.addSkipped(relPath, SkipCategorySymlinkFail, "symlink escapes repository root")
				return nil
			}
			// Re-stat the resolved target.
			info, err = os.Stat(resolved)
			if err != nil {
				w.addSkipped(relPath, SkipCategorySymlinkFail, fmt.Sprintf("cannot stat symlink target: %v", err))
				return nil
			}
			absPath = resolved
		}

		// Check for path traversal in the relative path.
		if containsTraversal(relPath) {
			w.addSkipped(relPath, SkipCategoryPathTraversal, "path contains traversal component")
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Enforce file count limit.
		if len(files) >= maxFiles {
			return fmt.Errorf("%w: maximum file count %d exceeded", ErrBudgetExhausted, maxFiles)
		}

		files = append(files, WalkedFile{
			Path:    relPath,
			AbsPath: absPath,
			Size:    info.Size(),
			Mode:    info.Mode(),
			IsDir:   info.IsDir(),
		})

		return nil
	})

	if err != nil {
		return files, fmt.Errorf("walking repository: %w", err)
	}

	if depthBudgetExceeded {
		return files, fmt.Errorf("%w: maximum depth %d exceeded", ErrBudgetExhausted, maxDepth)
	}

	return files, nil
}

// Skipped returns all entries that were skipped during the last Walk.
func (w *SafeWalker) Skipped() []SkippedEntry {
	return w.skipped
}

// SkippedCounts returns the saturating count of skip categories encountered.
func (w *SafeWalker) SkippedCounts() map[SkipCategory]int {
	m := make(map[SkipCategory]int, len(w.skippedCounts))
	for k, v := range w.skippedCounts {
		m[k] = v
	}
	return m
}

// SkippedOmitted returns the number of skip entries that exceeded the diagnostic budget.
func (w *SafeWalker) SkippedOmitted() int {
	return w.skippedOmitted
}

// Root returns the resolved repository root path.
func (w *SafeWalker) Root() string {
	return w.root
}

// IsExcluded reports whether a relative path or basename matches user-configured ExcludePatterns.
func (w *SafeWalker) IsExcluded(relPath, baseName string) bool {
	if w.excludedDirs != nil && w.excludedDirs[baseName] {
		return true
	}
	if w.config == nil || len(w.config.ExcludePatterns) == 0 {
		return false
	}
	slashPath := filepath.ToSlash(relPath)
	for _, pattern := range w.config.ExcludePatterns {
		p := filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(pattern), "./"))
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			continue
		}
		// Exact match on relative path or basename
		if slashPath == p || baseName == p {
			return true
		}
		// Path is inside excluded directory: e.g. pattern="dir", slashPath="dir/child"
		if strings.HasPrefix(slashPath, p+"/") {
			return true
		}
		// Glob match against relative path
		if matched, err := filepath.Match(p, slashPath); err == nil && matched {
			return true
		}
		// Glob match against base name
		if matched, err := filepath.Match(p, baseName); err == nil && matched {
			return true
		}
	}
	return false
}

// SafeReadFile reads a file within the repository with size limit enforcement.
// The path must be relative to the repository root.
func (w *SafeWalker) SafeReadFile(relPath string) ([]byte, error) {
	// Validate relative path does not contain traversal.
	if containsTraversal(relPath) {
		return nil, fmt.Errorf("path contains traversal: %s", relPath)
	}

	absPath := filepath.Join(w.root, relPath)

	// Resolve symlinks and verify the resolved path stays inside the root.
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}
	if !isInsideDir(resolved, w.root) {
		return nil, fmt.Errorf("resolved path escapes repository root")
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("is a directory: %s", relPath)
	}

	maxSize := w.config.maxFileSize()
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file exceeds size limit (%d > %d bytes)", info.Size(), maxSize)
	}

	maxAggregate := w.config.maxAggregateReadBytes()
	if maxAggregate > 0 {
		if maxAggregate-w.aggregateReadBytes < info.Size() {
			return nil, fmt.Errorf("%w: aggregate read budget exceeded", ErrBudgetExhausted)
		}
	}

	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	limit := maxSize
	bindingLimitIsAggregate := false
	if maxAggregate > 0 {
		rem := maxAggregate - w.aggregateReadBytes
		if rem < limit {
			limit = rem
			bindingLimitIsAggregate = true
		}
	}

	// Read with an explicit limit as a defense-in-depth measure,
	// even though we already checked the size via stat.
	data, err := io.ReadAll(io.LimitReader(f, limit))
	w.aggregateReadBytes += int64(len(data))

	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	postInfo, statErr := f.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("stat after read: %w", statErr)
	}

	if int64(len(data)) < postInfo.Size() {
		if int64(len(data)) == limit {
			if bindingLimitIsAggregate {
				return nil, fmt.Errorf("%w: aggregate read budget exceeded", ErrBudgetExhausted)
			}
			return nil, fmt.Errorf("file exceeds size limit during read")
		}
		return nil, fmt.Errorf("incomplete read: read %d bytes, file size is %d", len(data), postInfo.Size())
	}

	return data, nil
}

// isInsideDir checks whether path is inside (or equal to) dir.
// Both paths must be absolute and cleaned.
func isInsideDir(path, dir string) bool {
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, dir+string(filepath.Separator))
}

// containsTraversal checks if a relative path contains ".." components.
func containsTraversal(relPath string) bool {
	for _, part := range strings.Split(filepath.ToSlash(relPath), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// checkFilename validates a filename for safety issues.
// Returns a reason string if the filename is suspicious, or "" if safe.
func checkFilename(name string) string {
	if name == "" {
		return "empty filename"
	}
	if len(name) > 255 {
		return "filename exceeds 255 characters"
	}
	if strings.Contains(name, "\x00") {
		return "filename contains null byte"
	}
	if !utf8.ValidString(name) {
		return "filename contains invalid UTF-8"
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "filename contains control characters"
		}
	}
	return ""
}
