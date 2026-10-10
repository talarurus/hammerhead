package git

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

type snapshotRunner struct {
	root   string
	failAt string
	err    error
	status string
	calls  []string
}

func (r *snapshotRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	r.calls = append(r.calls, key)
	if key == r.failAt {
		return "?? misleading\x00", r.err
	}
	switch key {
	case "rev-parse --show-toplevel":
		return r.root + "\n", nil
	case "symbolic-ref --quiet HEAD":
		return "refs/heads/main\n", nil
	case "show-ref --verify --quiet refs/heads/main":
		return "", nil
	case "rev-parse --verify HEAD^{commit}":
		return "synthetic-object-id\n", nil
	case "status --porcelain=v1 -z --ignore-submodules=all":
		return r.status, nil
	default:
		panic(key)
	}
}

func TestGitSnapshot_NonRepoVsFailure(t *testing.T) {
	root, rootErr := filepath.EvalSymlinks(t.TempDir())
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	for _, tc := range []struct {
		name, stage   string
		err           error
		status        scanstate.CheckStatus
		applicability scanstate.GitApplicability
	}{
		{"nonrepo", "rev-parse --show-toplevel", &GitExitError{128, ErrNotARepository}, scanstate.CheckStatusNotApplicable, scanstate.GitNonRepository},
		{"unknown", "rev-parse --show-toplevel", &GitExitError{128, nil}, scanstate.CheckStatusPartial, scanstate.GitApplicabilityUnknown},
		{"permission", "rev-parse --show-toplevel", &GitExitError{128, ErrGitPermission}, scanstate.CheckStatusPartial, scanstate.GitApplicabilityUnknown},
		{"config", "rev-parse --show-toplevel", &GitExitError{128, ErrGitConfiguration}, scanstate.CheckStatusPartial, scanstate.GitApplicabilityUnknown},
		{"corrupt", "rev-parse --show-toplevel", &GitExitError{128, ErrGitCorrupt}, scanstate.CheckStatusPartial, scanstate.GitApplicabilityUnknown},
		{"timeout", "status --porcelain=v1 -z --ignore-submodules=all", ErrGitTimeout, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"stdout", "status --porcelain=v1 -z --ignore-submodules=all", ErrStdoutLimit, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"stderr", "status --porcelain=v1 -z --ignore-submodules=all", ErrStderrLimit, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"unknown-detached", "symbolic-ref --quiet HEAD", &GitExitError{1, nil}, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"unknown-unborn", "show-ref --verify --quiet refs/heads/main", &GitExitError{1, nil}, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"branch", "symbolic-ref --quiet HEAD", &GitExitError{128, nil}, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"ref", "show-ref --verify --quiet refs/heads/main", &GitExitError{128, ErrGitCorrupt}, scanstate.CheckStatusPartial, scanstate.GitRoot},
		{"cancelled", "status --porcelain=v1 -z --ignore-submodules=all", context.Canceled, scanstate.CheckStatusCancelled, scanstate.GitRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &snapshotRunner{root: root, failAt: tc.stage, err: tc.err}
			s, err := collectSnapshot(context.Background(), root, r)
			if s.Status != tc.status || s.Applicability != tc.applicability || s.Availability != scanstate.GitAvailable || s.ModifiedCount != 0 || s.UntrackedCount != 0 {
				t.Fatalf("%+v", s)
			}
			if tc.name == "nonrepo" {
				if err != nil || len(r.calls) != 1 {
					t.Fatal(err, r.calls)
				}
			} else if !errors.Is(err, tc.err) {
				t.Fatal(err)
			}
		})
	}
	r := &snapshotRunner{root: root, status: "?? good\x00 M truncated"}
	s, err := collectSnapshot(context.Background(), root, r)
	if !errors.Is(err, ErrMalformedGitOutput) || s.Status != scanstate.CheckStatusPartial || s.UntrackedCount != 0 {
		t.Fatal(s, err)
	}
}

func TestGitSnapshot_BranchStatesAndSubdirectory(t *testing.T) {
	root, rootErr := filepath.EvalSymlinks(t.TempDir())
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	for _, tc := range []struct {
		name, stage string
		err         error
		want        scanstate.GitBranchState
	}{
		{"normal", "", nil, scanstate.GitBranchNormal},
		{"unborn", "show-ref --verify --quiet refs/heads/main", &GitExitError{1, ErrUnbornBranch}, scanstate.GitBranchUnborn},
		{"detached", "symbolic-ref --quiet HEAD", &GitExitError{1, ErrDetachedHEAD}, scanstate.GitBranchDetached},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &snapshotRunner{root: root, failAt: tc.stage, err: tc.err}
			s, err := collectSnapshot(context.Background(), root, r)
			if err != nil || s.Status != scanstate.CheckStatusCompleted || s.BranchState != tc.want {
				t.Fatal(s, err)
			}
			calls := strings.Join(r.calls, "\n")
			if strings.Count(calls, "symbolic-ref") != 1 || strings.Count(calls, "status --porcelain") != 1 {
				t.Fatal(calls)
			}
		})
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	r := &snapshotRunner{root: root}
	s, err := collectSnapshot(context.Background(), sub, r)
	if err != nil || s.Applicability != scanstate.GitSubdirectory || s.Status != scanstate.CheckStatusNotApplicable || strings.Contains(strings.Join(r.calls, " "), "status --porcelain") {
		t.Fatal(s, err, r.calls)
	}
}

func TestGitExit_ClassificationIsNarrowAndSafe(t *testing.T) {
	ordinary := "fatal: not a git repository (or any of the parent directories): .git"
	for _, tc := range []struct {
		stderr string
		want   error
	}{
		{ordinary, ErrNotARepository},
		{ordinary + "\n", ErrNotARepository},
		{ordinary + "\r\n", ErrNotARepository},
		{ordinary + "\n\n", nil},
		{ordinary + " \n", nil},
		{" " + ordinary + "\n", nil},
		{ordinary + "\nsecret_sentinel", nil},
		{"fatal: detected dubious ownership in repository at 'secret_sentinel'", ErrGitPermission},
		{"fatal: cannot open secret_sentinel: Permission denied", ErrGitPermission},
		{"fatal: cannot open secret_sentinel: Permission denied\n", ErrGitPermission},
		{"fatal: cannot open secret_sentinel: Permission denied\r\n", ErrGitPermission},
		{"fatal: bad config line 1 in file secret_sentinel", ErrGitConfiguration},
		{"fatal: bad object secret_sentinel", ErrGitCorrupt},
		{"fatal: index file corrupt\n", ErrGitCorrupt},
		{"fatal: index file corrupt\r\n", ErrGitCorrupt},
		{"fatal: secret_sentinel unknown revision or path not in the working tree", nil},
	} {
		kind := classifyExit([]string{"rev-parse", "--show-toplevel"}, 128, tc.stderr)
		if kind != tc.want {
			t.Fatalf("%q: %v", tc.stderr, kind)
		}
		err := &GitExitError{128, kind}
		if strings.Contains(err.Error(), "secret_sentinel") {
			t.Fatal(err)
		}
	}
	if classifyExit([]string{"status"}, 128, ordinary) != nil || classifyExit([]string{"rev-parse", "--show-toplevel"}, 1, ordinary) != nil {
		t.Fatal("overbroad nonrepo classification")
	}
}

func TestGitExit_QuietBranchStateRequiresEmptyDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		expected error
	}{
		{[]string{"symbolic-ref", "--quiet", "HEAD"}, ErrDetachedHEAD},
		{[]string{"show-ref", "--verify", "--quiet", "refs/heads/main"}, ErrUnbornBranch},
	} {
		if kind := classifyExit(tc.args, 1, ""); kind != tc.expected {
			t.Fatal(kind)
		}
		for _, message := range []string{"\n", "\r\n", " ", "\t", " \t\r\n", "\n\n", "secret_sentinel\n", "fatal: unknown revision or path not in the working tree"} {
			if kind := classifyExit(tc.args, 1, message); kind != nil {
				t.Fatal("ignored branch diagnostics", kind)
			}
		}
		if kind := classifyExit(tc.args, 128, ""); kind != nil {
			t.Fatal(kind)
		}
	}
}

func TestGitSnapshot_AmbiguousDetectionProbeBound(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deep := root + strings.Repeat(string(filepath.Separator)+"d", MaxDetectionAncestorSteps+1)
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	r := &snapshotRunner{root: root, failAt: "rev-parse --show-toplevel", err: &GitExitError{128, ErrNotARepository}}
	s, err := collectSnapshot(context.Background(), deep, r)
	if !errors.Is(err, ErrGitDetectionAmbiguous) || s.Status != scanstate.CheckStatusPartial || s.Applicability != scanstate.GitApplicabilityUnknown || len(r.calls) != 1 {
		t.Fatal(s, err, r.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyNoGitMarker(ctx, deep); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
