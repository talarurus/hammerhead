package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/talarurus/hammerhead/internal/check"
	"github.com/talarurus/hammerhead/internal/engine"
	"github.com/talarurus/hammerhead/internal/fs"
)

func TestEngine_ThresholdDoesNotLeak(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("1234567890"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	reg := engine.NewRegistry()
	reg.Add(&check.LargeFileCheck{}) // Requires FILE-002
	eng := engine.New(reg)

	// Scan A: threshold 5, should flag the 10-byte file
	configA := &engine.ScanConfig{
		LargeFileThreshold: 5,
	}
	resA, err := eng.Scan(context.Background(), dir, configA)
	if err != nil {
		t.Fatalf("scan A failed: %v", err)
	}
	if resA.Status != "completed" {
		t.Errorf("Scan A expected completed status, got %s", resA.Status)
	}
	if len(resA.Findings) != 1 || resA.Findings[0].RuleID != "FILE-002" {
		t.Errorf("Scan A expected 1 FILE-002 finding, got %d", len(resA.Findings))
	}

	// Scan B: threshold 0 (default: 50MB), should NOT flag the 10-byte file
	configB := &engine.ScanConfig{
		LargeFileThreshold: 0,
	}
	resB, err := eng.Scan(context.Background(), dir, configB)
	if err != nil {
		t.Fatalf("scan B failed: %v", err)
	}
	if resB.Status != "completed" {
		t.Errorf("Scan B expected completed status, got %s", resB.Status)
	}
	if len(resB.Findings) != 0 {
		t.Errorf("Scan B expected 0 findings, got %d", len(resB.Findings))
	}
}

func TestEngine_ConcurrentScanOptions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("1234567890"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	reg := engine.NewRegistry()
	reg.Add(&check.LargeFileCheck{})
	eng := engine.New(reg)

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var threshold int64
			var expectedFindings int
			if idx%2 == 0 {
				threshold = 5 // Expect finding
				expectedFindings = 1
			} else {
				threshold = 15 // Expect no finding
				expectedFindings = 0
			}

			config := &engine.ScanConfig{
				LargeFileThreshold: threshold,
			}
			res, err := eng.Scan(context.Background(), dir, config)
			if err != nil {
				errCh <- fmt.Errorf("goroutine %d failed: %w", idx, err)
				return
			}
			if len(res.Findings) != expectedFindings {
				errCh <- fmt.Errorf("goroutine %d expected %d findings, got %d", idx, expectedFindings, len(res.Findings))
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

func TestEngine_DoesNotMutateConfigBackingArrays(t *testing.T) {
	dir := t.TempDir()

	reg := engine.NewRegistry()
	eng := engine.New(reg)

	// Create slice with spare capacity to detect append() overwriting backing array
	originalPatterns := make([]string, 1, 5)
	originalPatterns[0] = "foo"

	walkerPatterns := make([]string, 1, 5)
	walkerPatterns[0] = "bar"

	config := &engine.ScanConfig{
		ExcludePatterns: originalPatterns,
		Walker: &fs.WalkerConfig{
			ExcludePatterns: walkerPatterns,
		},
	}

	_, err := eng.Scan(context.Background(), dir, config)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(originalPatterns) != 1 || originalPatterns[0] != "foo" {
		t.Errorf("backing array mutated (length or elements)! %v", originalPatterns)
	}

	// Check if elements beyond length were mutated
	originalPatterns = originalPatterns[:cap(originalPatterns)]
	if originalPatterns[1] != "" {
		t.Errorf("backing array spare capacity was overwritten! %v", originalPatterns)
	}

	if len(walkerPatterns) != 1 || walkerPatterns[0] != "bar" {
		t.Errorf("walker backing array mutated (length or elements)! %v", walkerPatterns)
	}

	walkerPatterns = walkerPatterns[:cap(walkerPatterns)]
	if walkerPatterns[1] != "" {
		t.Errorf("walker backing array spare capacity was overwritten! %v", walkerPatterns)
	}
}
