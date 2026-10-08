package fs_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/fs"
)

func TestSafeWalker_NormalFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file structure
	if err := os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Should have file1.txt, subdir, subdir/file2.txt
	filePaths := make(map[string]bool)
	for _, f := range files {
		filePaths[f.Path] = true
	}

	if !filePaths["file1.txt"] {
		t.Errorf("file1.txt not found in walk results")
	}
	if !filePaths[filepath.Join("subdir", "file2.txt")] {
		t.Errorf("subdir/file2.txt not found in walk results")
	}
}

func TestSafeWalker_SymlinkEscapesRoot(t *testing.T) {
	tempDir := t.TempDir()
	outsideDir := t.TempDir()

	// File outside repo
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("super secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Symlink inside repo pointing outside
	symlinkPath := filepath.Join(tempDir, "escaped_link")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		t.Skip("Symlinks not supported in this environment")
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	for _, f := range files {
		if f.Path == "escaped_link" {
			t.Errorf("expected escaped symlink to be excluded, but it was walked: %+v", f)
		}
	}

	// Verify it was recorded in skipped entries
	skipped := walker.Skipped()
	found := false
	for _, s := range skipped {
		if s.Path == "escaped_link" && strings.Contains(s.Reason, "escapes repository root") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("escaped symlink was not recorded in SkippedEntries: %+v", skipped)
	}
}

func TestSafeWalker_SymlinkWithinRoot(t *testing.T) {
	tempDir := t.TempDir()

	realFile := filepath.Join(tempDir, "real.txt")
	if err := os.WriteFile(realFile, []byte("legitimate data"), 0o600); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(tempDir, "link_to_real.txt")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Skip("Symlinks not supported")
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	foundLink := false
	for _, f := range files {
		if f.Path == "link_to_real.txt" {
			foundLink = true
			if f.Size != int64(len("legitimate data")) {
				t.Errorf("expected size %d, got %d", len("legitimate data"), f.Size)
			}
		}
	}
	if !foundLink {
		t.Errorf("safe in-repo symlink was unexpectedly excluded")
	}
}

func TestSafeWalker_ExcludedDirectories(t *testing.T) {
	tempDir := t.TempDir()

	// Create excluded dirs: .git, node_modules, vendor, .venv
	dirsToExclude := []string{".git", "node_modules", "vendor", ".venv"}
	for _, d := range dirsToExclude {
		dirPath := filepath.Join(tempDir, d)
		if err := os.Mkdir(dirPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dirPath, "ignored.txt"), []byte("noise"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	for _, f := range files {
		for _, d := range dirsToExclude {
			if strings.HasPrefix(f.Path, d) {
				t.Errorf("file from excluded directory %q was walked: %s", d, f.Path)
			}
		}
	}
}

func TestSafeWalker_ErrBudgetExhausted(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("b"), 0644)

	cfg := &fs.WalkerConfig{
		MaxFiles: 1,
	}

	walker, err := fs.NewSafeWalker(tmpDir, cfg)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	_, walkErr := walker.Walk()
	if walkErr == nil {
		t.Fatalf("expected walk error, got nil")
	}

	if !errors.Is(walkErr, fs.ErrBudgetExhausted) {
		t.Errorf("expected walkErr to be ErrBudgetExhausted, got: %v", walkErr)
	}
}

func TestSafeWalker_DepthBudgetExhausted(t *testing.T) {
	tempDir := t.TempDir()

	// Create directory nesting 5 deep: a/b/c/d/e/deep.txt
	deepPath := filepath.Join(tempDir, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deepPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepPath, "deep.txt"), []byte("deep"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create a shallow file
	if err := os.WriteFile(filepath.Join(tempDir, "shallow.txt"), []byte("shallow"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set max depth to 2
	walker, err := fs.NewSafeWalker(tempDir, &fs.WalkerConfig{
		MaxDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, walkErr := walker.Walk()
	if walkErr == nil {
		t.Fatalf("Walk succeeded, expected budget exhausted error")
	}
	if !errors.Is(walkErr, fs.ErrBudgetExhausted) {
		t.Fatalf("expected ErrBudgetExhausted, got: %v", walkErr)
	}

	shallowFound := false
	for _, f := range files {
		if strings.Contains(f.Path, "shallow.txt") {
			shallowFound = true
		}
		if strings.Contains(f.Path, "deep.txt") {
			t.Errorf("file beyond max depth was walked: %s", f.Path)
		}
	}
	if !shallowFound {
		t.Errorf("shallow file was not collected before depth error")
	}

	skipped := walker.Skipped()
	foundDepthSkip := false
	for _, s := range skipped {
		if strings.Contains(s.Reason, "exceeded max depth") {
			foundDepthSkip = true
			break
		}
	}
	if !foundDepthSkip {
		t.Errorf("depth skip not recorded in SkippedEntries")
	}
}

func TestSafeWalker_MaxFiles(t *testing.T) {
	tempDir := t.TempDir()

	for i := 0; i < 15; i++ {
		name := filepath.Join(tempDir, filepath.Base(t.Name())+string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	walker, err := fs.NewSafeWalker(tempDir, &fs.WalkerConfig{
		MaxFiles: 5,
	})
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	_, err = walker.Walk()
	if err == nil {
		t.Fatalf("expected error when file count limit exceeded, got nil")
	}
	if !errors.Is(err, fs.ErrBudgetExhausted) {
		t.Errorf("expected ErrBudgetExhausted, got: %v", err)
	}
}

func TestSafeWalker_SafeReadFile(t *testing.T) {
	tempDir := t.TempDir()

	filePath := filepath.Join(tempDir, "test.txt")
	content := []byte("test content")
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	walker, err := fs.NewSafeWalker(tempDir, &fs.WalkerConfig{
		MaxFileSize: 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Normal read within limit
	data, err := walker.SafeReadFile("test.txt")
	if err != nil {
		t.Fatalf("SafeReadFile failed: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("got %q, want %q", string(data), string(content))
	}

	// 2. Traversal attempt
	_, err = walker.SafeReadFile("../outside.txt")
	if err == nil {
		t.Errorf("expected traversal path to fail, got nil")
	}

	// 3. File exceeding size limit
	bigFile := filepath.Join(tempDir, "big.txt")
	if err := os.WriteFile(bigFile, []byte("this content is strictly longer than twenty bytes limit"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = walker.SafeReadFile("big.txt")
	if err == nil {
		t.Errorf("expected size limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSafeWalker_ExcludePatterns(t *testing.T) {
	tempDir := t.TempDir()

	// Create directory structure:
	// - normal.go
	// - bundle.min.js
	// - fixtures/dirty/bad.key
	// - custom_vendor/dep.go
	if err := os.WriteFile(filepath.Join(tempDir, "normal.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "bundle.min.js"), []byte("var a=1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "fixtures", "dirty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "fixtures", "dirty", "bad.key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "custom_vendor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "custom_vendor", "dep.go"), []byte("package dep"), 0o600); err != nil {
		t.Fatal(err)
	}

	walker, err := fs.NewSafeWalker(tempDir, &fs.WalkerConfig{
		ExcludePatterns: []string{
			"fixtures/dirty",
			"*.min.js",
			"custom_vendor",
		},
	})
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	paths := make(map[string]bool)
	for _, f := range files {
		paths[filepath.ToSlash(f.Path)] = true
	}

	if !paths["normal.go"] {
		t.Errorf("expected normal.go to be walked")
	}
	if paths["bundle.min.js"] {
		t.Errorf("bundle.min.js should have been excluded by pattern *.min.js")
	}
	if paths["fixtures/dirty"] || paths["fixtures/dirty/bad.key"] {
		t.Errorf("fixtures/dirty should have been excluded by path pattern")
	}
	if paths["custom_vendor"] || paths["custom_vendor/dep.go"] {
		t.Errorf("custom_vendor should have been excluded by dirname pattern")
	}

	// Verify skipped entries record "excluded by user pattern"
	skipped := walker.Skipped()
	var foundDirty, foundMin, foundVendor bool
	for _, s := range skipped {
		if s.Reason == "excluded by user pattern" {
			switch filepath.ToSlash(s.Path) {
			case "fixtures/dirty":
				foundDirty = true
			case "bundle.min.js":
				foundMin = true
			case "custom_vendor":
				foundVendor = true
			}
		}
	}

	if !foundDirty {
		t.Errorf("fixtures/dirty was not recorded as skipped by user pattern")
	}
	if !foundMin {
		t.Errorf("bundle.min.js was not recorded as skipped by user pattern")
	}
	if !foundVendor {
		t.Errorf("custom_vendor was not recorded as skipped by user pattern")
	}
}

func TestSafeWalker_BrokenSymlink(t *testing.T) {
	tempDir := t.TempDir()
	symlinkPath := filepath.Join(tempDir, "broken_link")
	if err := os.Symlink(filepath.Join(tempDir, "does_not_exist.txt"), symlinkPath); err != nil {
		t.Skip("Symlinks not supported")
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Should not crash and should skip the broken link
	for _, f := range files {
		if f.Path == "broken_link" {
			t.Errorf("broken symlink was unexpectedly included in Walk results")
		}
	}

	skipped := walker.Skipped()
	found := false
	for _, s := range skipped {
		if s.Path == "broken_link" && strings.Contains(s.Reason, "cannot stat symlink target") {
			found = true
			break
		}
	}
	// Note: EvalSymlinks returns an error on broken symlinks so it might be "unresolvable symlink"
	if !found {
		for _, s := range skipped {
			if s.Path == "broken_link" && strings.Contains(s.Reason, "unresolvable symlink") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("broken symlink was not recorded in SkippedEntries correctly: %+v", skipped)
	}
}

func TestSafeWalker_SymlinkLoop(t *testing.T) {
	tempDir := t.TempDir()
	linkA := filepath.Join(tempDir, "linkA")
	linkB := filepath.Join(tempDir, "linkB")

	if err := os.Symlink(linkB, linkA); err != nil {
		t.Skip("Symlinks not supported")
	}
	if err := os.Symlink(linkA, linkB); err != nil {
		t.Skip("Symlinks not supported")
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	_, err = walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed due to symlink loop (expected it to be skipped): %v", err)
	}
}

func TestSafeWalker_MalformedFilenames(t *testing.T) {
	tempDir := t.TempDir()

	// Adversarial filenames that can realistically be created on POSIX filesystems.
	// Note: POSIX filesystems (macOS, Linux) disallow filenames containing NUL (0x00)
	// bytes because kernel/VFS syscalls use null-terminated strings. Attempting to create
	// a file containing a NUL byte fails at the OS syscall level (EINVAL). SafeWalker's
	// defense-in-depth handling of NUL bytes is unit-tested in TestCheckFilename.
	malformedCandidates := []string{
		"newline_\n_file.txt",
		"ansi_\x1b[31m_chars.txt",
		"control_\x07_bell.txt",
	}

	createdMalformed := make(map[string]bool)
	for _, name := range malformedCandidates {
		err := os.WriteFile(filepath.Join(tempDir, name), []byte("malformed content"), 0600)
		if err != nil {
			t.Logf("OS filesystem rejected creating filename %q: %v", name, err)
			continue
		}
		createdMalformed[name] = true
	}

	// Attempt invalid UTF-8 filename if the host filesystem permits it.
	// macOS APFS rejects invalid UTF-8 with EINVAL/Errno 92; Linux ext4 permits arbitrary non-NUL byte sequences.
	invalidUTF8Name := "invalid_utf8_\xff\xfe.txt"
	if err := os.WriteFile(filepath.Join(tempDir, invalidUTF8Name), []byte("invalid utf-8"), 0600); err == nil {
		createdMalformed[invalidUTF8Name] = true
	} else {
		t.Logf("OS filesystem rejected creating invalid UTF-8 filename: %v", err)
	}

	// Create a safe file starting with a hyphen (leading "-" is valid POSIX, but tests flag-injection safety).
	hyphenFile := "-hyphen_file.txt"
	if err := os.WriteFile(filepath.Join(tempDir, hyphenFile), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	walker, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatalf("NewSafeWalker failed: %v", err)
	}

	files, err := walker.Walk()
	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Verify no malformed files were yielded.
	for _, f := range files {
		if strings.Contains(f.Path, "\x1b") || strings.Contains(f.Path, "\x00") || strings.Contains(f.Path, "\n") || strings.Contains(f.Path, "\x07") {
			t.Errorf("Walk unexpectedly yielded a file with control characters: %q", f.Path)
		}
	}

	// Verify created malformed files were recorded in Skipped with control character reason.
	skippedMap := make(map[string]string)
	for _, s := range walker.Skipped() {
		skippedMap[s.Path] = s.Reason
	}
	for name := range createdMalformed {
		reason, ok := skippedMap[name]
		if !ok {
			t.Errorf("Expected malformed file %q to be recorded in SkippedEntries, but was not", name)
		} else if strings.Contains(name, "invalid_utf8") {
			if !strings.Contains(reason, "invalid UTF-8") {
				t.Errorf("Expected file %q to be skipped for invalid UTF-8, got reason: %q", name, reason)
			}
		} else if !strings.Contains(reason, "control characters") {
			t.Errorf("Expected file %q to be skipped for control characters, got reason: %q", name, reason)
		}
	}

	// Verify leading hyphen file was safely walked and yielded.
	foundHyphen := false
	for _, f := range files {
		if f.Path == hyphenFile {
			foundHyphen = true
			break
		}
	}
	if !foundHyphen {
		t.Errorf("Walk unexpectedly skipped a valid file starting with a hyphen: %s", hyphenFile)
	}
}

func TestCheckFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected string
	}{
		{
			name:     "empty filename",
			filename: "",
			expected: "empty filename",
		},
		{
			name:     "filename exceeds 255 characters",
			filename: strings.Repeat("a", 256),
			expected: "filename exceeds 255 characters",
		},
		{
			name:     "null byte",
			filename: "null_\x00_byte.txt",
			expected: "filename contains null byte",
		},
		{
			name:     "newline character",
			filename: "file_\n_name.txt",
			expected: "filename contains control characters",
		},
		{
			name:     "ANSI escape character",
			filename: "file_\x1b_name.txt",
			expected: "filename contains control characters",
		},
		{
			name:     "bell control character",
			filename: "file_\x07_name.txt",
			expected: "filename contains control characters",
		},
		{
			name:     "carriage return character",
			filename: "file_\r_name.txt",
			expected: "filename contains control characters",
		},
		{
			name:     "tab character",
			filename: "file_\t_name.txt",
			expected: "filename contains control characters",
		},
		{
			name:     "valid normal filename",
			filename: "normal_file.txt",
			expected: "",
		},
		{
			name:     "valid leading hyphen",
			filename: "-hyphen_file.txt",
			expected: "",
		},
		{
			name:     "valid unicode filename",
			filename: "file_日本語_test.txt",
			expected: "",
		},
		{
			name:     "invalid UTF-8",
			filename: "invalid_utf8_\xff\xfe.txt",
			expected: "filename contains invalid UTF-8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fs.CheckFilename(tc.filename)
			if got != tc.expected {
				t.Errorf("CheckFilename(%q) = %q; want %q", tc.filename, got, tc.expected)
			}
		})
	}
}

func TestSafeWalker_SkippedBudget(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 5; i++ {
		err := os.Mkdir(filepath.Join(tmpDir, fmt.Sprintf("dir%d", i)), 0755)
		if err != nil {
			t.Fatal(err)
		}
		os.Mkdir(filepath.Join(tmpDir, fmt.Sprintf("dir%d", i), "sub"), 0755)
	}

	// Set MaxDiagnosticSamples equivalent
	cfg := &fs.WalkerConfig{
		MaxSkippedEntries:    3,
		MaxExamplesPerReason: 2,
		MaxDiagnosticPath:    10,
		MaxSafeMessage:       10,
		MaxDepth:             1,
	}

	walker, err := fs.NewSafeWalker(tmpDir, cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = walker.Walk()

	skipped := walker.Skipped()

	// MaxExamplesPerReason is 2, so it should have saved exactly 2 entries.
	if len(skipped) != 2 {
		t.Fatalf("expected 2 skipped entries, got %d", len(skipped))
	}

	if walker.SkippedOmitted() != 3 {
		t.Errorf("expected 3 omitted, got %d", walker.SkippedOmitted())
	}

	if walker.SkippedCounts()[fs.SkipCategoryDepthExceeded] != 5 {
		t.Errorf("expected 5 total counted for category, got %d", walker.SkippedCounts()[fs.SkipCategoryDepthExceeded])
	}

	// Check truncation
	for _, s := range skipped {
		if len(s.Path) > 10 {
			t.Errorf("path exceeded 10 chars: %s", s.Path)
		}
		if len(s.Reason) > 10 {
			t.Errorf("reason exceeded 10 chars: %s", s.Reason)
		}
	}
}

func TestSafeWalker_SkippedCountsCopy(t *testing.T) {
	tempDir := t.TempDir()
	w, err := fs.NewSafeWalker(tempDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Internal state might be empty initially. Let's add a test hook or walk a broken symlink.
	symlinkPath := filepath.Join(tempDir, "broken_link")
	os.Symlink(filepath.Join(tempDir, "does_not_exist.txt"), symlinkPath)
	w.Walk()

	counts := w.SkippedCounts()
	// Mutate
	counts[fs.SkipCategorySymlinkFail] = 9999

	countsAgain := w.SkippedCounts()
	if countsAgain[fs.SkipCategorySymlinkFail] == 9999 {
		t.Errorf("SkippedCounts returned mutable internal map")
	}
}

func TestSafeWalker_SafeReadFileIncompleteRead(t *testing.T) {
	tempDir := t.TempDir()

	file1 := filepath.Join(tempDir, "file1.txt")
	os.WriteFile(file1, make([]byte, 100), 0644)

	walker, _ := fs.NewSafeWalker(tempDir, &fs.WalkerConfig{
		MaxFileSize: 50,
	})

	// This should fail early in os.Stat due to size limit
	_, err := walker.SafeReadFile("file1.txt")
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}
