package git

import (
	"errors"
	"strings"
	"testing"
)

func TestMetadata_InertBranchSubsections(t *testing.T) {
	for _, name := range []string{"main", "v0.2-dev", "release/1.2", "feature.foo", "feature.remote", "a_b-c/D.e", strings.Repeat("a", 255)} {
		for _, setting := range []string{"remote", "merge"} {
			for _, value := range []string{"origin", "refs/heads/main", "", "!not-executed", "../../not-read", "$(never-run)", "[core]\nfsmonitor = not-live\n"} {
				key := "branch." + name + "." + setting
				config, err := projectConfig(key + "\n" + value + "\x00")
				if err != nil || config != generatedConfig(nil) {
					t.Fatalf("inert branch key %q leaked/failed: %q %v", key, config, err)
				}
			}
		}
	}
	for _, name := range []string{"", ".", "..", ".main", "main.", "a..b", "a//b", "/main", "main/", "a./b", "a/.b", "a.lock", "a.lock/b", "-main", "@", "a@{b", "a b", "a\tb", "a\nb", "a\\b", "a:b", "a*b", "a[b", "a\"b", "a\x00b", strings.Repeat("a", 256)} {
		for _, setting := range []string{"remote", "merge"} {
			if _, err := projectConfig("branch." + name + "." + setting + "\nopaque\x00"); !errors.Is(err, ErrUnsafeGitMetadata) {
				t.Fatalf("malformed branch %q admitted: %v", name, err)
			}
		}
	}
	for _, key := range []string{"branch.main", "branch.main.", "branch.main.clean", "branch.v0.2-dev.rebase", "branch.release/1.2.mergeOptions", "branch.feature.foo.fsmonitor", "branch.main.remote.command", "branch.main.merge.path", "branch.main.remotehelper", "branch.main.merger", "branch.main.Remote", "Branch.main.remote", "branchx.main.remote", "filter.main.clean", "include.path", "includeIf.onbranch:main.path", "core.worktree", "core.fsmonitor", "core.hooksPath", "remote.origin.uploadpack", "remote.origin.promisor", "remote.origin.extra.url"} {
		if _, err := projectConfig(key + "\nopaque\x00"); !errors.Is(err, ErrUnsafeGitMetadata) {
			t.Fatalf("unexpected key %q admitted: %v", key, err)
		}
	}
	// A later inert key cannot hide an earlier unreviewed directive or vice versa.
	for _, records := range []string{"include.path\nnot-read\x00branch.v0.2-dev.remote\norigin\x00", "branch.v0.2-dev.remote\norigin\x00filter.fixture.clean\nnot-executed\x00"} {
		if _, err := projectConfig(records); !errors.Is(err, ErrUnsafeGitMetadata) {
			t.Fatal("inert branch bypassed finite policy", err)
		}
	}
}
