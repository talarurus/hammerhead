package fs

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParseByteSize parses a human-readable size string (e.g. "50MB", "10KB", "1GB", "1024B", "50M")
// into bytes.
//
// Rules:
//   - Supported units: B, KB, MB, GB (case-insensitive, optional trailing 'B' like 'M' or 'MB').
//   - Fractional numbers are supported: "1.5MB" -> 1572864 bytes.
//   - Values <= 0 are rejected with an error.
//   - Strings with invalid characters, missing numbers, or unknown units return an error.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty byte size string")
	}

	// Find where numeric part ends and unit begins
	splitIdx := -1
	for i, r := range s {
		if !unicode.IsDigit(r) && r != '.' && r != '+' && r != '-' {
			splitIdx = i
			break
		}
	}

	var numStr, unitStr string
	if splitIdx == -1 {
		numStr = s
		unitStr = "b" // default to bytes if no unit
	} else {
		numStr = strings.TrimSpace(s[:splitIdx])
		unitStr = strings.ToLower(strings.TrimSpace(s[splitIdx:]))
	}

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", numStr, err)
	}

	if val <= 0 {
		return 0, fmt.Errorf("file size must be greater than 0, got %v", val)
	}

	var multiplier float64
	switch unitStr {
	case "b", "bytes", "byte":
		multiplier = 1
	case "k", "kb", "kib":
		multiplier = 1024
	case "m", "mb", "mib":
		multiplier = 1024 * 1024
	case "g", "gb", "gib":
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size unit %q (supported: B, KB, MB, GB)", unitStr)
	}

	result := int64(val * multiplier)
	if result <= 0 {
		return 0, fmt.Errorf("file size overflow or invalid: %v", val)
	}

	return result, nil
}
