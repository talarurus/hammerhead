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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
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
	MaxDepth        int      // Maximum directory depth (0 = use default)
	MaxFiles        int      // Maximum number of files to yield (0 = use default)
	MaxFileSize     int64    // Maximum file size in bytes for content reading (0 = use default)
	ExtraDirs       []string // Additional directory names to exclude
	ExcludePatterns []string // Glob/path patterns to exclude (e.g. "testdata/repos/dirty", "*.min.js", "vendor")
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

// defaultExcludedDirs are directories that are always skipped during traversal.
// These are either metadata directories, build outputs, or dependency caches
// that produce massive false-positive volumes without security value.
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

// SafeWalker performs bounded, symlink-aware filesystem traversal.
type SafeWalker struct {
	root         string
	config       *WalkerConfig
	excludedDirs map[string]bool
	skipped      []SkippedEntry
}

// SkippedEntry records a file or directory that was skipped during traversal.
type SkippedEntry struct {
	Path   string // Relative path
	Reason string // Why it was skipped
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
		root:         resolvedRoot,
		config:       config,
		excludedDirs: excluded,
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
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   relPath,
				Reason: fmt.Sprintf("walk error: %v", walkErr),
			})
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Compute relative path.
		relPath, err := filepath.Rel(w.root, absPath)
		if err != nil {
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   absPath,
				Reason: "failed to compute relative path",
			})
			return nil
		}

		// Skip the root directory entry itself.
		if relPath == "." {
			return nil
		}

		// Check user-configured exclude patterns.
		if w.isExcluded(relPath, filepath.Base(relPath)) {
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   relPath,
				Reason: "excluded by user pattern",
			})
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check for malicious filenames.
		if reason := checkFilename(filepath.Base(relPath)); reason != "" {
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   relPath,
				Reason: reason,
			})
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check directory depth.
		depth := strings.Count(relPath, string(filepath.Separator)) + 1
		if depth > maxDepth {
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   relPath,
				Reason: fmt.Sprintf("exceeded max depth (%d)", maxDepth),
			})
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
				w.skipped = append(w.skipped, SkippedEntry{
					Path:   relPath,
					Reason: "excluded directory",
				})
				return filepath.SkipDir
			}
		}

		// Handle symlinks.
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(absPath)
			if err != nil {
				w.skipped = append(w.skipped, SkippedEntry{
					Path:   relPath,
					Reason: fmt.Sprintf("unresolvable symlink: %v", err),
				})
				return nil
			}
			if !isInsideDir(resolved, w.root) {
				w.skipped = append(w.skipped, SkippedEntry{
					Path:   relPath,
					Reason: "symlink escapes repository root",
				})
				return nil
			}
			// Re-stat the resolved target.
			info, err = os.Stat(resolved)
			if err != nil {
				w.skipped = append(w.skipped, SkippedEntry{
					Path:   relPath,
					Reason: fmt.Sprintf("cannot stat symlink target: %v", err),
				})
				return nil
			}
			absPath = resolved
		}

		// Check for path traversal in the relative path.
		if containsTraversal(relPath) {
			w.skipped = append(w.skipped, SkippedEntry{
				Path:   relPath,
				Reason: "path contains traversal component",
			})
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

// Root returns the resolved repository root path.
func (w *SafeWalker) Root() string {
	return w.root
}

// isExcluded reports whether a relative path or basename matches user-configured ExcludePatterns.
func (w *SafeWalker) isExcluded(relPath, baseName string) bool {
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

	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// Read with an explicit limit as a defense-in-depth measure,
	// even though we already checked the size via stat.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file exceeds size limit during read")
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
	for _, r := range name {
		if unicode.IsControl(r) {
			return "filename contains control characters"
		}
	}
	return ""
}

// IsBinaryFile checks if a file appears to be binary by inspecting its first bytes.
// Uses the same approach as net/http: read up to 512 bytes and detect content type.
func IsBinaryFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	if n == 0 {
		return false, nil // Empty file is not binary.
	}

	contentType := http.DetectContentType(buf[:n])
	// text/* and application/json are treated as text.
	if strings.HasPrefix(contentType, "text/") {
		return false, nil
	}
	if contentType == "application/json" {
		return false, nil
	}
	// application/octet-stream and everything else is binary.
	return true, nil
}
