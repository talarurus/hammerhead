package fs

import (
	"fmt"
	"math/big"
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

	// Decimal sizes must not round through float64: large in-range integers
	// lose precision and out-of-range floats may convert to a positive int64.
	val, ok := new(big.Rat).SetString(numStr)
	if !ok {
		return 0, fmt.Errorf("invalid number %q", numStr)
	}

	if val.Sign() <= 0 {
		return 0, fmt.Errorf("file size must be greater than 0, got %v", val)
	}

	var multiplier int64
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

	bytes := new(big.Int).Mul(val.Num(), big.NewInt(multiplier))
	bytes.Quo(bytes, val.Denom()) // Preserve established fractional-byte truncation.
	if !bytes.IsInt64() || bytes.Sign() <= 0 {
		return 0, fmt.Errorf("file size overflow or invalid: %v", val)
	}

	return bytes.Int64(), nil
}
