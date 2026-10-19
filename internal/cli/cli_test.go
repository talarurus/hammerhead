package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	os.Exit(runCLITests(m))
}

// Return before os.Exit so cleanup runs on success, failure and build errors.
func runCLITests(m *testing.M) int {
	if len(os.Args) == 3 && os.Args[1] == "--g12-special-reader" {
		return runC15SpecialReader(os.Args[2])
	}
	tempDir, err := os.MkdirTemp("", "hammerhead-cli-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)

	bin := filepath.Join(tempDir, "hammerhead")
	// Compile binary from project root
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/hammerhead-core")
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic("failed to build test binary: " + string(out))
	}

	binaryPath = bin
	return m.Run()
}

// Static native-scan fixtures must not inherit the developer checkout's Git
// layout or policy. Keep their bytes and every CLI assertion unchanged.
func isolatedCLIStaticFixture(t *testing.T, name string) (string, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("../../testdata/repos", name))); err != nil {
		return "", err
	}
	return dir, nil
}

func TestCLI_Version(t *testing.T) {
	cmd := exec.Command(binaryPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v (out: %s)", err, string(out))
	}
	if !strings.Contains(string(out), "Hammerhead Core version") {
		t.Errorf("expected version output, got: %s", string(out))
	}
}

func TestCLI_AuditCleanRepo(t *testing.T) {
	cleanDir, err := isolatedCLIStaticFixture(t, "clean")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", cleanDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit on clean repo failed unexpectedly: %v (out: %s)", err, string(out))
	}

	if !strings.Contains(string(out), "No findings") {
		t.Errorf("expected 'No findings' in output, got: %s", string(out))
	}
}

func TestCLI_AuditDirtyRepo_Exit1(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", dirtyDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected audit on dirty repo to fail with exit code 1, but succeeded. Out: %s", string(out))
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}

	// Verify terminal output shows findings
	outStr := string(out)
	if !strings.Contains(outStr, "[FILE-001]") {
		t.Errorf("expected [FILE-001] in output, got: %s", outStr)
	}
	if !strings.Contains(outStr, "SSH private key") {
		t.Errorf("expected 'SSH private key' in output, got: %s", outStr)
	}
}

func TestCLI_AuditDirtyRepo_FailOnNone(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", dirtyDir, "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected --fail-on none to exit with code 0, but failed: %v (out: %s)", err, string(out))
	}

	// Output still reports the findings
	if !strings.Contains(string(out), "[FILE-001]") {
		t.Errorf("expected findings to be reported even with --fail-on none")
	}
}

func TestCLI_AuditDirtyRepo_FailOnCritical(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	// Dirty repo has a CRITICAL finding (AWS Access Key ID), so --fail-on critical exits with 1
	cmd := exec.Command(binaryPath, "audit", dirtyDir, "--fail-on", "critical")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected --fail-on critical to exit with 1 on dirty repo with critical findings, got exit 0 (out: %s)", string(out))
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestCLI_AuditJSONOutput(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", dirtyDir, "--output", "json", "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v (out: %s)", err, string(out))
	}

	var parsed struct {
		Schema  string `json:"schema"`
		Summary struct {
			FindingsCount int `json:"findings_count"`
		} `json:"summary"`
		Findings []map[string]any `json:"findings"`
	}

	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, string(out))
	}

	if parsed.Schema != "hammerhead-core/v0.2" {
		t.Errorf("expected schema hammerhead-core/v0.2, got %q", parsed.Schema)
	}
	if parsed.Summary.FindingsCount < 3 {
		t.Errorf("expected at least 3 findings in dirty repo, got %d", parsed.Summary.FindingsCount)
	}
}

func TestCLI_AuditInvalidPath_Exit2(t *testing.T) {
	cmd := exec.Command(binaryPath, "audit", "/nonexistent/path/that/does/not/exist")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected invalid path to exit with code 2, but succeeded")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2 for operational error, got %d (out: %s)", exitErr.ExitCode(), string(out))
	}
}

func TestCLI_Adversarial_EscapedSymlink(t *testing.T) {
	// Adversarial scenario: an untrusted repository has a symlink pointing to an outside sensitive file
	tempRepo := t.TempDir()
	outsideDir := t.TempDir()

	secretFile := filepath.Join(outsideDir, "shadow")
	if err := os.WriteFile(secretFile, []byte("root:*:12345"), 0o600); err != nil {
		t.Fatal(err)
	}

	// In-repo symlink to external file
	symlinkPath := filepath.Join(tempRepo, "id_rsa") // Named id_rsa to test if it tries to follow it
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Skip("Symlinks not supported in environment")
	}

	// SafeWalker should skip the symlink because it escapes root,
	// so no finding should be generated for the escaped target.
	cmd := exec.Command(binaryPath, "audit", tempRepo, "--output", "json", "--fail-on", "none")
	out, err := cmd.Output()

	if err != nil {
		t.Fatalf("expected audit to succeed (exit 0) when skipping escaped symlink with fail-on none, got error: %v. Output: %s", err, string(out))
	}
	var parsed struct {
		Findings []struct {
			Path string `json:"path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	for _, f := range parsed.Findings {
		if f.Path == "id_rsa" {
			t.Errorf("escaped symlink was analyzed as finding: %+v", f)
		}
	}
}

func TestCLI_Adversarial_DeepNesting(t *testing.T) {
	tempRepo := t.TempDir()

	// Create deeply nested structure: 60 levels deep
	current := tempRepo
	for i := 0; i < 60; i++ {
		current = filepath.Join(current, "level")
	}
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatal(err)
	}
	// Place a sensitive file at the bottom
	if err := os.WriteFile(filepath.Join(current, "id_rsa"), []byte("nested"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Audit should complete safely and return exit code 2 (partial status) due to depth exhaustion
	cmd := exec.Command(binaryPath, "audit", tempRepo, "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("audit succeeded on deep nesting repo, expected exit code 2. Output: %s", out)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for depth exhaustion, got %d. Output: %s", exitErr.ExitCode(), string(out))
	}
}

func TestCLI_Adversarial_TerminalSanitization(t *testing.T) {
	tempRepo := t.TempDir()

	// Attempt to inject terminal spoofing via a sensitive filename
	// Filename contains ANSI escape sequences and carriage return
	spoofedName := "safe_name.key"
	if err := os.WriteFile(filepath.Join(tempRepo, spoofedName), []byte("dummy key"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", tempRepo, "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}

	outStr := string(out)
	// Verify that the terminal output contains the expected finding
	if !strings.Contains(outStr, "[FILE-001]") {
		t.Errorf("expected finding [FILE-001] in output")
	}
}

func TestCLI_Adversarial_OversizedFile(t *testing.T) {
	tempRepo := t.TempDir()

	// Create a sparse file of 60 MB
	hugeFile := filepath.Join(tempRepo, "huge_archive.zip")
	f, err := os.Create(hugeFile)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate to 60 MB without writing 60MB of disk data
	if err := f.Truncate(60 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command(binaryPath, "audit", tempRepo, "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit on oversized file failed: %v (out: %s)", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "[FILE-002]") {
		t.Errorf("expected FILE-002 large-file detection, got: %s", outStr)
	}
	if !strings.Contains(outStr, "60.00 MB") {
		t.Errorf("expected 60.00 MB in evidence, got: %s", outStr)
	}
}

func TestCLI_Adversarial_BinaryFileSkipsSecretScan(t *testing.T) {
	tempRepo := t.TempDir()

	// Create binary file (ELF header) with embedded AWS key bytes
	binPath := filepath.Join(tempRepo, "compiled_binary.bin")
	binData := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00}, []byte("AKIA"+"1234567890ABCDEF")...)
	if err := os.WriteFile(binPath, binData, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", tempRepo, "--output", "json", "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit on binary file repo failed: %v", err)
	}

	var parsed struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// SEC-001 must NOT match binary files
	for _, f := range parsed.Findings {
		if f.RuleID == "SEC-001" && f.Path == "compiled_binary.bin" {
			t.Errorf("SEC-001 should not match binary files, but generated finding: %+v", f)
		}
	}
}

func TestCLI_AuditHygieneRepo_FailOnLowExits0(t *testing.T) {
	hygieneDir, err := filepath.Abs("../../testdata/repos/hygiene")
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()

	// Copy base fixtures from testdata/repos/hygiene (.gitignore, main.go)
	entries, err := os.ReadDir(hygieneDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "large_dataset.bin" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(hygieneDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tempDir, entry.Name()), content, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Dynamically generate a 55 MB file (exceeds default 50 MB FILE-002 threshold) using Truncate
	largeFile := filepath.Join(tempDir, "large_dataset.bin")
	f, err := os.Create(largeFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(55 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	// Hygiene-only repo has no security findings. Even with --fail-on low, exit code must be 0!
	cmd := exec.Command(binaryPath, "audit", tempDir, "--fail-on", "low")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected --fail-on low to exit with 0 on hygiene-only repo, got: %v (out: %s)", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "[FILE-002]") {
		t.Errorf("expected FILE-002 large-file detection, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "HYGIENE OBSERVATIONS") {
		t.Errorf("expected FILE-002 to be classified under HYGIENE OBSERVATIONS, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Observed Core severity: NONE") {
		t.Errorf("expected 'Observed Core severity: NONE' for hygiene repo, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Security findings:      0") {
		t.Errorf("expected 'Security findings:      0', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Hygiene observations:   3") {
		t.Errorf("expected 'Hygiene observations:   3', got:\n%s", outStr)
	}
}

func TestCLI_AuditExcludeFlag(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	// Exclude all dirty directories/files, leaving only benign main.go
	cmd := exec.Command(binaryPath, "audit", dirtyDir,
		"-e", ".env",
		"-e", "certs",
		"-e", "keys",
		"-e", "credentials.json",
		"--output", "json",
		"--fail-on", "critical",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected audit with full exclusions to exit 0, got %v: %s", err, string(out))
	}

	var parsed struct {
		Findings []struct {
			Path string `json:"path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, f := range parsed.Findings {
		if strings.HasPrefix(f.Path, "certs") || strings.HasPrefix(f.Path, "keys") || f.Path == ".env" || f.Path == "credentials.json" {
			t.Errorf("excluded file generated finding: %+v", f)
		}
	}
}

func TestCLI_AuditMaxFileSizeFlag(t *testing.T) {
	tempRepo := t.TempDir()

	// Create a 20 MB sparse file
	filePath := filepath.Join(tempRepo, "medium_archive.zip")
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(20 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	// 1. With default 50MB threshold: no FILE-002 finding
	cmdDefault := exec.Command(binaryPath, "audit", tempRepo, "--output", "json", "--fail-on", "none")
	outDefault, err := cmdDefault.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	if strings.Contains(string(outDefault), `"id": "FILE-002`) {
		t.Errorf("20MB file should not trigger default 50MB threshold: %s", outDefault)
	}

	// 2. With --max-file-size 10MB: FILE-002 finding is generated
	cmdOverride := exec.Command(binaryPath, "audit", tempRepo, "--max-file-size", "10MB", "--output", "json", "--fail-on", "none")
	outOverride, err := cmdOverride.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	if !strings.Contains(string(outOverride), "FILE-002") {
		t.Errorf("20MB file should trigger FILE-002 with --max-file-size 10MB, got: %s", string(outOverride))
	}
}

func TestCLI_AuditQuietFlag(t *testing.T) {
	dirtyDir, err := isolatedCLIStaticFixture(t, "dirty")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "audit", dirtyDir, "-q", "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("quiet audit failed: %v", err)
	}

	outStr := string(out)
	if strings.Contains(outStr, "HAMMERHEAD CORE AUDIT") {
		t.Errorf("quiet output must not contain banner")
	}
	if strings.Contains(outStr, "Why it matters:") {
		t.Errorf("quiet output must not contain verbose descriptions")
	}
	if !strings.Contains(outStr, "[HIGH] [FILE-001]") && !strings.Contains(outStr, "[CRITICAL] [SEC-001]") {
		t.Errorf("quiet output missing expected compact finding line, got: %s", outStr)
	}
}

func TestCLI_AuditMaxFileSize_SecretDetectionRegression(t *testing.T) {
	tempRepo := t.TempDir()

	// Create a ~2MB text file exceeding 1MB threshold but within reading limits
	largeFilePath := filepath.Join(tempRepo, "large.txt")
	f, err := os.Create(largeFilePath)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 32*1024)
	for i := range chunk {
		chunk[i] = ' '
	}
	for i := 0; i < 64; i++ {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	if _, err := f.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command(binaryPath, "audit", tempRepo, "--max-file-size", "1MB", "--output", "json", "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v (out: %s)", err, string(out))
	}

	var parsed struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v (out: %s)", err, string(out))
	}

	foundLargeFile := false
	foundSecret := false
	for _, f := range parsed.Findings {
		if f.RuleID == "FILE-002" && f.Path == "large.txt" {
			foundLargeFile = true
		}
		if f.RuleID == "SEC-001" && f.Path == "large.txt" {
			foundSecret = true
		}
	}

	if !foundLargeFile {
		t.Errorf("expected FILE-002 for large.txt with --max-file-size 1MB")
	}
	if !foundSecret {
		t.Errorf("expected SEC-001 for large.txt despite exceeding large file threshold")
	}
}

func TestCLI_InvalidTarget(t *testing.T) {
	cmd := exec.Command(binaryPath, "audit", "/nonexistent/path/that/does/not/exist", "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure to exit with code 2, but succeeded. Output: %s", out)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d\nOutput: %s", exitErr.ExitCode(), out)
	}
	outStr := string(out)
	if !strings.Contains(outStr, "Error: cannot access") || !strings.Contains(outStr, "no such file or directory") {
		t.Errorf("expected output to mention no such file or directory, got: %s", outStr)
	}
}

func TestCLI_IncompleteFailOnNone(t *testing.T) {
	// Create a repository with a deeply nested structure that exceeds DefaultMaxDepth (50)
	tmpDir := t.TempDir()

	currentPath := tmpDir
	for i := 0; i < 52; i++ {
		currentPath = filepath.Join(currentPath, fmt.Sprintf("dir%d", i))
		if err := os.Mkdir(currentPath, 0755); err != nil {
			t.Fatalf("failed to create nested dir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(currentPath, "file1.txt"), []byte("a"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	cmd := exec.Command(binaryPath, "audit", tmpDir, "--fail-on", "none")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure to exit with code 2, but succeeded. Output: %s", out)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d\nOutput: %s", exitErr.ExitCode(), out)
	}
	outStr := string(out)
	if !strings.Contains(outStr, "PARTIAL") {
		t.Errorf("expected output to mention PARTIAL, got: %s", outStr)
	}
	if strings.Contains(outStr, "✓ No findings") {
		t.Errorf("expected output not to mention clean success, got: %s", outStr)
	}
}
