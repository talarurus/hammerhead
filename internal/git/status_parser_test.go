package git

import (
	"context"
	"errors"
	"testing"
)

func TestPorcelainZ_RenameAndControlNames(t *testing.T) {
	for _, tc := range []struct {
		out                 string
		modified, untracked int
	}{
		{"", 0, 0},
		{"R  destination\n\t\" -> name\x00source\r\nname\x00?? \n\tfile\x00 M tracked\nname\x00", 2, 1},
		{" C copied\x00old\x00!! ignored\x00UU conflict\x00", 2, 0},
		{"?? ?? name\x00??  leading space\x00", 0, 2},
	} {
		m, u, err := parsePorcelainZ(context.Background(), tc.out)
		if err != nil || m != tc.modified || u != tc.untracked {
			t.Fatalf("%q: counts %d,%d error %v", tc.out, m, u, err)
		}
	}
}

func TestPorcelainZ_MalformedAndTruncated(t *testing.T) {
	for _, out := range []string{
		"?? good\x00 M truncated", "R  new\x00", "R  new\x00old", "R  new\x00\x00",
		"?? \x00", "??xfile\x00", "\x00", "ZZ bad\x00", "  clean\x00", "?M mixed\x00",
		"?? good\x00\x00", "U  invalid\x00",
	} {
		m, u, err := parsePorcelainZ(context.Background(), out)
		if !errors.Is(err, ErrMalformedGitOutput) || m != 0 || u != 0 {
			t.Errorf("accepted %q: %d,%d %v", out, m, u, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, out := range []string{"", "?? file\x00"} {
		if _, _, err := parsePorcelainZ(ctx, out); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func FuzzPorcelainZ(f *testing.F) {
	for _, out := range []string{"", "?? file\x00", "R  dest\x00source\x00", "?? good\x00 M bad"} {
		f.Add(out)
	}
	f.Fuzz(func(t *testing.T, out string) {
		m, u, err := parsePorcelainZ(context.Background(), out)
		if m < 0 || u < 0 || (err != nil && (m != 0 || u != 0)) {
			t.Fatalf("invalid counts %d,%d %v", m, u, err)
		}
	})
}
