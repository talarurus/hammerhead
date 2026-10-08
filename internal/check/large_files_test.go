package check_test

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
)

func TestLargeFileCheck(t *testing.T) {
	c := &check.LargeFileCheck{}

	files := []check.FileInfo{
		{Path: "small.txt", Size: 1024, IsDir: false},
		{Path: "medium.zip", Size: 5 * 1024 * 1024, IsDir: false},
		{Path: "large.iso", Size: 15 * 1024 * 1024, IsDir: false},
		{Path: "big_dir", Size: 50 * 1024 * 1024, IsDir: true}, // Directory should be ignored
	}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files:    files,
		Options: check.CheckOptions{
			LargeFileThresholdBytes: 10 * 1024 * 1024, // 10 MB for test
		},
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Path != "large.iso" {
		t.Errorf("expected finding for large.iso, got %s", f.Path)
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("expected severity Low, got %v", f.Severity)
	}
	if f.Confidence != finding.ConfidenceHigh {
		t.Errorf("expected confidence High, got %v", f.Confidence)
	}
	if f.RuleID != "FILE-002" {
		t.Errorf("expected rule ID FILE-002, got %s", f.RuleID)
	}
}

func TestLargeFileCheck_DefaultThreshold(t *testing.T) {
	c := &check.LargeFileCheck{} // 0 = default 50 MB

	files := []check.FileInfo{
		{Path: "40mb.bin", Size: 40 * 1024 * 1024, IsDir: false},
		{Path: "60mb.bin", Size: 60 * 1024 * 1024, IsDir: false},
	}

	sc := &check.ScanContext{
		RepoRoot: "/dummy",
		Files:    files,
	}

	findings, err := runCheckForTest(c, sc)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(findings) != 1 || findings[0].Path != "60mb.bin" {
		t.Fatalf("expected 1 finding for 60mb.bin, got %+v", findings)
	}
}
