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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

	MaxExaminedEntries int
	MaxDirectoryWidth  int
	DirectoryReadBatch int
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

func (c *WalkerConfig) maxExaminedEntries() int {
	if c != nil && c.MaxExaminedEntries > 0 {
		return c.MaxExaminedEntries
	}
	return 100_000
}

func (c *WalkerConfig) maxDirectoryWidth() int {
	if c != nil && c.MaxDirectoryWidth > 0 {
		return c.MaxDirectoryWidth
	}
	return 10_000
}

func (c *WalkerConfig) directoryReadBatch() int {
	batch := 256
	if c != nil && c.DirectoryReadBatch > 0 {
		batch = c.DirectoryReadBatch
	}
	if batch > 256 {
		return 256
	}
	return batch
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
	SkipCategoryWalkError              SkipCategory = "walk_error"
	SkipCategoryRelativePathFail       SkipCategory = "relative_path_fail"
	SkipCategoryUserExcluded           SkipCategory = "user_excluded"
	SkipCategoryMaliciousName          SkipCategory = "malicious_name"
	SkipCategoryDepthExceeded          SkipCategory = "depth_exceeded"
	SkipCategoryExcludedDir            SkipCategory = "excluded_dir"
	SkipCategorySymlinkFail            SkipCategory = "symlink_fail"
	SkipCategoryPathTraversal          SkipCategory = "path_traversal"
	SkipCategoryWidthExceeded          SkipCategory = "width_exceeded"
	SkipCategoryExaminedBudgetExceeded SkipCategory = "examined_budget_exceeded"
	SkipCategoryRetainedBudgetExceeded SkipCategory = "retained_budget_exceeded"
	SkipCategoryGitfile                SkipCategory = "gitfile"
	SkipCategoryCancelled              SkipCategory = "cancelled"
	SkipCategoryNonRegular             SkipCategory = "non_regular"
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

var ErrRootSetupFailed = errors.New("failed to set up root directory")

var testHookAfterReadDirBatch func()

type fileMeta struct {
	dev  uint64
	ino  uint64
	mode os.FileMode
	size int64
}

func (f fileMeta) IsDir() bool {
	return f.mode.IsDir()
}

func (f fileMeta) IsRegular() bool {
	return f.mode.IsRegular()
}

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

func (w *SafeWalker) Walk(ctx context.Context) ([]WalkedFile, Inventory, error) {
	var files []WalkedFile
	inv := Inventory{
		SkipCounts:        make(map[SkipCategory]int),
		RootREADME:        PresenceUnknown,
		RootLICENSE:       PresenceUnknown,
		RootGitignore:     PresenceUnknown,
		InventoryComplete: true,
		RootListComplete:  true,
	}

	rootF, rootChain, rootMeta, err := openRoot(w.root)
	if err != nil {
		w.addSkipped(".", SkipCategoryWalkError, err.Error())
		inv.InventoryComplete = false
		inv.RootListComplete = false
		return files, inv, fmt.Errorf("%w: %v", ErrRootSetupFailed, err)
	}
	defer rootF.Close()

	files = append(files, WalkedFile{
		Path:    ".",
		AbsPath: w.root,
		Size:    rootMeta.size,
		Mode:    rootMeta.mode,
		IsDir:   true,
	})
	inv.RetainedDirs++

	err = w.walkDir(ctx, rootF, rootChain, ".", w.root, 1, &files, &inv)
	if err != nil {
		inv.InventoryComplete = false
	}

	// populate SkipCounts for inventory
	for cat, count := range w.SkippedCounts() {
		inv.SkipCounts[cat] = count
	}

	if err == nil && inv.DepthExhausted {
		err = fmt.Errorf("%w: depth budget exhausted", ErrBudgetExhausted)
	}
	return files, inv, err
}

func (w *SafeWalker) walkDir(ctx context.Context, dirF *os.File, chain []dirEntry, relPath, absPath string, depth int, files *[]WalkedFile, inv *Inventory) error {
	if err := validateChain(chain); err != nil {
		w.addSkipped(relPath, SkipCategoryWalkError, err.Error())
		inv.InventoryComplete = false
		if relPath == "." {
			inv.RootListComplete = false
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		w.addSkipped(relPath, SkipCategoryCancelled, "cancelled")
		inv.InventoryComplete = false
		if relPath == "." {
			inv.RootListComplete = false
		}
		return err
	}

	var entries []os.DirEntry
	var excludedREADME, excludedLICENSE, excludedGitignore bool
	for {
		if err := ctx.Err(); err != nil {
			w.addSkipped(relPath, SkipCategoryCancelled, "cancelled")
			inv.InventoryComplete = false
			if relPath == "." {
				inv.RootListComplete = false
			}
			return err
		}
		remExamined := w.config.maxExaminedEntries() - inv.ExaminedEntries
		if remExamined < 0 {
			remExamined = 0
		}
		remWidth := w.config.maxDirectoryWidth() - len(entries)
		if remWidth < 0 {
			remWidth = 0
		}
		limit := remExamined
		if remWidth < limit {
			limit = remWidth
		}
		limit += 1 // Allow one extra to prove overflow

		batchSize := w.config.directoryReadBatch()
		if limit < batchSize {
			batchSize = limit
		}

		batch, err := dirF.ReadDir(batchSize)
		if testHookAfterReadDirBatch != nil {
			testHookAfterReadDirBatch()
		}

		if len(batch) > 0 {
			entries = append(entries, batch...)
			inv.ExaminedEntries += len(batch)
			if inv.ExaminedEntries > w.config.maxExaminedEntries() {
				w.addSkipped(relPath, SkipCategoryExaminedBudgetExceeded, "examined budget exceeded")
				inv.InventoryComplete = false
				if relPath == "." {
					inv.RootListComplete = false
				}
				return fmt.Errorf("%w: examined budget exceeded", ErrBudgetExhausted)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			w.addSkipped(relPath, SkipCategoryWalkError, err.Error())
			inv.InventoryComplete = false
			if relPath == "." {
				inv.RootListComplete = false
			}
			return err
		}
		if len(entries) > w.config.maxDirectoryWidth() {
			break
		}
	}

	if len(entries) > w.config.maxDirectoryWidth() {
		w.addSkipped(relPath, SkipCategoryWidthExceeded, "directory width exceeded")
		if relPath == "." {
			inv.RootListComplete = false
		}
		return fmt.Errorf("%w: directory width exceeded", ErrBudgetExhausted)
	}

	type child struct {
		name  string
		isDir bool
		meta  fileMeta
	}
	var children []child

	// Select skip samples only after a complete bounded listing. Over-cap
	// listings above are discarded rather than traversed from a readdir prefix.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {

		name := e.Name()

		lowerName := strings.ToLower(name)
		if name == ".git" {
			w.addSkipped(filepath.Join(relPath, name), SkipCategoryGitfile, "gitfile or dir")
			continue
		}

		markSkippedCandidate := func() {
			if relPath == "." {
				if isREADME(lowerName) {
					excludedREADME = true
				}
				if isLICENSE(lowerName) {
					excludedLICENSE = true
				}
				if name == ".gitignore" {
					excludedGitignore = true
				}
			}
		}

		if w.IsExcluded(filepath.Join(relPath, name), name) {
			w.addSkipped(filepath.Join(relPath, name), SkipCategoryUserExcluded, "excluded by user pattern")
			markSkippedCandidate()
			continue
		}

		if reason := checkFilename(name); reason != "" {
			w.addSkipped(filepath.Join(relPath, name), SkipCategoryMaliciousName, reason)
			markSkippedCandidate()
			continue
		}

		// Get direct child metadata securely
		fm, err := statRelative(chain, name)
		if err != nil {
			w.addSkipped(filepath.Join(relPath, name), SkipCategoryWalkError, "stat failed")
			inv.InventoryComplete = false
			markSkippedCandidate()
			continue
		}

		isDir := fm.IsDir()

		if isDir && w.excludedDirs[name] {
			w.addSkipped(filepath.Join(relPath, name), SkipCategoryExcludedDir, "excluded directory")
			markSkippedCandidate()
			continue
		}

		if fm.mode&os.ModeSymlink != 0 {
			symlinkLogicalPath := filepath.Join(relPath, name)

			targetFm, err := resolveSymlinkRelative(ctx, chain, relPath, name, w.IsExcluded)
			if err != nil {
				w.addSkipped(symlinkLogicalPath, SkipCategorySymlinkFail, fmt.Sprintf("cannot resolve symlink target: %v", err))
				markSkippedCandidate()
				continue
			}

			if targetFm.IsDir() {
				w.addSkipped(symlinkLogicalPath, SkipCategorySymlinkFail, "do not follow directory symlinks")
				markSkippedCandidate()
				continue
			}

			if !targetFm.IsRegular() {
				w.addSkipped(symlinkLogicalPath, SkipCategorySymlinkFail, "do not follow non-regular symlinks")
				markSkippedCandidate()
				continue
			}

			fm.size = targetFm.size
			fm.mode = targetFm.mode
			isDir = false
		}

		if relPath == "." {
			lower := strings.ToLower(name)
			if fm.IsRegular() {
				if isREADME(lower) {
					inv.RootREADME = PresencePresent
					excludedREADME = false
				}
				if isLICENSE(lower) {
					inv.RootLICENSE = PresencePresent
					excludedLICENSE = false
				}
				if name == ".gitignore" {
					inv.RootGitignore = PresencePresent
					excludedGitignore = false
				}
			}
		}

		children = append(children, child{name: name, isDir: isDir, meta: fm})
	}

	if relPath == "." {
		if inv.RootREADME == PresenceUnknown {
			if !inv.RootListComplete || excludedREADME {
				inv.RootREADME = PresenceUnknown
			} else {
				inv.RootREADME = PresenceAbsent
			}
		}
		if inv.RootLICENSE == PresenceUnknown {
			if !inv.RootListComplete || excludedLICENSE {
				inv.RootLICENSE = PresenceUnknown
			} else {
				inv.RootLICENSE = PresenceAbsent
			}
		}
		if inv.RootGitignore == PresenceUnknown {
			if !inv.RootListComplete || excludedGitignore {
				inv.RootGitignore = PresenceUnknown
			} else {
				inv.RootGitignore = PresenceAbsent
			}
		}
	}

	sort.Slice(children, func(i, j int) bool {
		return children[i].name < children[j].name
	})

	for _, c := range children {
		if err := ctx.Err(); err != nil {
			w.addSkipped(relPath, SkipCategoryCancelled, "cancelled")
			inv.InventoryComplete = false
			return err
		}

		childRelPath := filepath.Join(relPath, c.name)
		childAbsPath := filepath.Join(absPath, c.name)

		if !c.isDir && !c.meta.IsRegular() {
			w.addSkipped(childRelPath, SkipCategoryNonRegular, "non-regular file")
			continue
		}

		if len(*files) >= w.config.maxFiles() {
			w.addSkipped(relPath, SkipCategoryRetainedBudgetExceeded, "retained budget exceeded")
			inv.InventoryComplete = false
			return fmt.Errorf("%w: retained budget exceeded", ErrBudgetExhausted)
		}

		if c.isDir {
			if depth >= w.config.maxDepth() {
				w.addSkipped(childRelPath, SkipCategoryDepthExceeded, fmt.Sprintf("exceeded max depth (%d)", w.config.maxDepth()))
				inv.DepthExhausted = true
				inv.InventoryComplete = false
				continue
			}

			childF, childChain, childMeta, err := openDirRelative(chain, c.name, c.meta, childAbsPath)
			if err != nil {
				w.addSkipped(childRelPath, SkipCategoryWalkError, err.Error())
				inv.InventoryComplete = false
				continue
			}

			*files = append(*files, WalkedFile{
				Path:    childRelPath,
				AbsPath: childAbsPath,
				Size:    childMeta.size,
				Mode:    childMeta.mode,
				IsDir:   true,
			})
			inv.RetainedDirs++

			err = w.walkDir(ctx, childF, childChain, childRelPath, childAbsPath, depth+1, files, inv)
			childF.Close()
			if err != nil {
				return err
			}
		} else {

			*files = append(*files, WalkedFile{
				Path:    childRelPath,
				AbsPath: childAbsPath,
				Size:    c.meta.size,
				Mode:    c.meta.mode,
				IsDir:   false,
			})
			inv.RetainedFiles++
		}
	}

	return nil
}

func (w *SafeWalker) Skipped() []SkippedEntry {
	res := make([]SkippedEntry, len(w.skipped))
	copy(res, w.skipped)
	sort.Slice(res, func(i, j int) bool {
		a, b := res[i], res[j]
		ap, bp := strings.ReplaceAll(a.Path, "\\", "/"), strings.ReplaceAll(b.Path, "\\", "/")
		if ap != bp {
			return ap < bp
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Path < b.Path
	})
	return res
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
