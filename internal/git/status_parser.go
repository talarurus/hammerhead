package git

import (
	"context"
	"strings"
)

// parsePorcelainZ counts entries, never lines or paths. In porcelain v1 -z a
// rename/copy entry has destination first, followed by the source NUL record.
// Output is already bounded by the runner; this consumes it without a split
// allocation proportional to the number of names. Failure discards all counts.
func parsePorcelainZ(ctx context.Context, out string) (modified, untracked int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	for out != "" {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		record, rest, ok := strings.Cut(out, "\x00")
		if !ok || len(record) < 4 || record[2] != ' ' {
			return 0, 0, ErrMalformedGitOutput
		}
		xy := record[:2]
		if !validStatus(xy) {
			return 0, 0, ErrMalformedGitOutput
		}
		out = rest
		if strings.ContainsAny(xy, "RC") {
			source, rest, ok := strings.Cut(out, "\x00")
			if !ok || source == "" {
				return 0, 0, ErrMalformedGitOutput
			}
			out = rest
		}
		if xy == "??" {
			untracked++
		} else if xy != "!!" {
			modified++
		}
	}
	return modified, untracked, nil
}

func validStatus(xy string) bool {
	// Exact documented porcelain v1 combinations, including unmerged entries.
	switch xy {
	case "??", "!!", "DD", "AU", "UD", "UA", "DU", "AA", "UU":
		return true
	}
	x, y := xy[0], xy[1]
	if x == ' ' {
		return strings.ContainsRune("MTADRC", rune(y))
	}
	if !strings.ContainsRune("MTARC", rune(x)) && x != 'D' {
		return false
	}
	if y == ' ' {
		return true
	}
	if x == 'D' {
		return false
	}
	return strings.ContainsRune("MTDRC", rune(y))
}
