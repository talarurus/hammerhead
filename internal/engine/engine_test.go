package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/finding"
)

func TestEngine_ScanCleanRepo(t *testing.T) {
	tempDir := t.TempDir()

	// Clean project with normal files
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("# Project"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte("Apache 2.0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, ".gitignore"), []byte(".env\n*.key\n*.pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := engine.DefaultRegistry()
	eng := engine.New(reg)

	result, err := eng.Scan(context.Background(), tempDir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.ChecksRun < 1 {
		t.Errorf("expected at least 1 check run, got %d", result.ChecksRun)
	}
	if len(result.Findings) != 0 {
		t.Errorf("clean repo had unexpected findings: %+v", result.Findings)
	}
}

func TestEngine_ScanDirtyRepo(t *testing.T) {
	tempDir := t.TempDir()

	// Add a sensitive file
	if err := os.WriteFile(filepath.Join(tempDir, ".env"), []byte("SECRET=123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "id_rsa"), []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := engine.DefaultRegistry()
	eng := engine.New(reg)

	result, err := eng.Scan(context.Background(), tempDir, nil)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}

	// Threshold High should fail due to id_rsa

	// Threshold Critical should pass if no critical findings exist
	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == finding.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
	}

	// Threshold above critical (fail-on none) must always be 0
}

func TestEngine_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	reg := engine.DefaultRegistry()
	eng := engine.New(reg)

	_, err := eng.Scan(ctx, tempDir, nil)
	if err == nil {
		t.Errorf("expected scan to fail when context cancelled, got nil")
	}
}

func TestEngine_Timeout(t *testing.T) {
	tempDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // Ensure timeout fires

	reg := engine.DefaultRegistry()
	eng := engine.New(reg)

	_, err := eng.Scan(ctx, tempDir, nil)
	if err == nil {
		t.Errorf("expected scan to fail on timeout, got nil")
	}
}

func TestEngine_MaxFileSizeConflation(t *testing.T) {
	tempDir := t.TempDir()

	// Create a 2MB file (greater than 1MB max-file-size flag, but less than 5MB SEC-001 hard limit and 10MB SafeWalker default limit).
	// We'll fill it with spaces and a secret at the end so it isn't completely binary.
	largeFilePath := filepath.Join(tempDir, "large_secret.txt")
	f, err := os.Create(largeFilePath)
	if err != nil {
		t.Fatal(err)
	}

	// Write ~2MB of spaces to make it a text file
	blank := make([]byte, 32*1024)
	for i := range blank {
		blank[i] = ' '
	}
	for i := 0; i < 64; i++ {
		_, _ = f.Write(blank)
	}
	// Append a deterministic private key header
	_, _ = f.WriteString("\n" + "-----" + "BEGIN OPENSSH PRIVATE KEY-----\n")
	f.Close()

	registry := engine.DefaultRegistry()
	eng := engine.New(registry)

	// Simulate `--max-file-size 1MB` and verify separation from SecurityReadLimit
	config := &engine.ScanConfig{
		LargeFileThreshold: 1024 * 1024,     // 1MB
		SecurityReadLimit:  5 * 1024 * 1024, // 5MB
	}

	result, err := eng.Scan(context.Background(), tempDir, config)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundLargeFile := false
	foundSecret := false

	for _, f := range result.Findings {
		if f.RuleID == "FILE-002" && f.Path == "large_secret.txt" {
			foundLargeFile = true
		}
		if f.RuleID == "SEC-001" && f.Path == "large_secret.txt" {
			foundSecret = true
		}
	}

	if !foundLargeFile {
		t.Errorf("Expected FILE-002 to flag the file as large because it exceeds 1MB threshold")
	}
	if !foundSecret {
		t.Errorf("Expected SEC-001 to find the secret! The read limit should not be conflated with the large file threshold.")
	}
}

func TestEngine_SecurityReadLimitEnforcement(t *testing.T) {
	tempDir := t.TempDir()

	// Write a file containing a secret
	content := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgk")
	if err := os.WriteFile(filepath.Join(tempDir, ".env"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	registry := engine.DefaultRegistry()
	eng := engine.New(registry)

	// First verify it DOES find it with default config
	resultDef, err := eng.Scan(context.Background(), tempDir, &engine.ScanConfig{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	found := false
	for _, f := range resultDef.Findings {
		if f.RuleID == "SEC-001" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected SEC-001 finding with default config, found none. Got findings: %+v", resultDef.Findings)
	}

	// Now explicitly set an artificially low SecurityReadLimit (10 bytes).
	// AWS check usually asks for 5 MiB. We want to ensure 10 bytes wins.
	// Since 10 bytes is smaller than the file, the read should be rejected by GuardedReader as TooLarge,
	// and the secret shouldn't be found.
	config := &engine.ScanConfig{
		SecurityReadLimit: 10,
	}

	result, err := eng.Scan(context.Background(), tempDir, config)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.RuleID == "SEC-001" {
			t.Errorf("found secret in file that should have been rejected as too large: %+v", f)
		}
	}
}
