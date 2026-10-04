package fs_test

import (
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/fs"
)

func TestParseByteSize_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"50MB", 50 * 1024 * 1024},
		{"50mb", 50 * 1024 * 1024},
		{"50M", 50 * 1024 * 1024},
		{"10KB", 10 * 1024},
		{"10k", 10 * 1024},
		{"1GB", 1 * 1024 * 1024 * 1024},
		{"1g", 1 * 1024 * 1024 * 1024},
		{"512B", 512},
		{"512", 512},
		{"1.5MB", int64(1.5 * 1024 * 1024)},
		{"  100 MB  ", 100 * 1024 * 1024},
	}

	for _, tt := range tests {
		got, err := fs.ParseByteSize(tt.input)
		if err != nil {
			t.Errorf("ParseByteSize(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("ParseByteSize(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestParseByteSize_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"0",
		"0MB",
		"-10MB",
		"abc",
		"50TB",
		"50foo",
		"--50MB",
	}

	for _, input := range invalid {
		got, err := fs.ParseByteSize(input)
		if err == nil {
			t.Errorf("ParseByteSize(%q) expected error, got %d", input, got)
		}
	}
}
