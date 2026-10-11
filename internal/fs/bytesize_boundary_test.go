package fs_test

import (
	"strconv"
	"testing"

	"github.com/talarurus/hammerhead/internal/fs"
)

func TestParseByteSize_Boundaries(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"1B", 1}, {"010B", 10}, {"08", 8}, {"0.999KB", 1022}, {".5KB", 512},
		{"9223372036854775807", 9223372036854775807},
		{"9007199254740993B", 9007199254740993},
		{"8589934591.999999999GB", 9223372036854775806},
	} {
		got, err := fs.ParseByteSize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%q = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"9223372036854775808", "8589934592GB", "999999999999999999999999GB", "0.1B", "NaN", "Inf", "1e100", "1\x00MB", "1\n2MB", "١٢MB", "1..2MB"} {
		if got, err := fs.ParseByteSize(in); err == nil {
			t.Errorf("invalid/overflow %q accepted as %d", in, got)
		}
	}
}

func FuzzParseByteSize(f *testing.F) {
	for _, s := range []string{"1", "010", "08", "1.5MB", "9223372036854775807", "9007199254740993", "9223372036854775808", "0.1B", "NaN", "Inf", "-1KB", "١٢MB", "1\x1b[31mMB", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := fs.ParseByteSize(s)
		if err == nil {
			if n <= 0 {
				t.Fatalf("accepted nonpositive %d", n)
			}
			round, err := fs.ParseByteSize(strconv.FormatInt(n, 10))
			if err != nil || round != n {
				t.Fatalf("successful byte count cannot round-trip: %q -> %d -> %d, %v", s, n, round, err)
			}
		}
		// Every in-range positive decimal integer must be represented exactly.
		if want, err := strconv.ParseInt(s, 10, 64); err == nil && want > 0 {
			if n != want {
				t.Fatalf("integer precision lost: %q -> %d want %d", s, n, want)
			}
		}
	})
}
