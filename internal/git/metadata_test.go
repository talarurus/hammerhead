//go:build darwin || linux

package git

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/scanstate"
	"golang.org/x/sys/unix"
)

// These fixtures contain no executable helper definitions, remote services or
// sentinels. All setup commands precede any refusal-only config mutation.
func metadataFixture(t *testing.T, unborn bool) (string, *GitRunner) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	root := t.TempDir()
	template := t.TempDir()
	r, err := NewGitRunner(root)
	if err != nil {
		t.Fatal(err)
	}
	fixtureCommand(t, r, root, "init", "--template="+template, "-b", "main")
	if !unborn {
		metadataWrite(t, filepath.Join(root, "tracked.txt"), "AAAAAAAA\n")
		fixtureCommand(t, r, root, "add", ".")
		fixtureCommand(t, r, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
	}
	return root, r
}
func metadataWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixtureCommand(t *testing.T, r *GitRunner, root string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.gitPath, append([]string{"--no-pager", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_CONFIG_HOME=" + os.Getenv("XDG_CONFIG_HOME"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1", "GIT_ATTR_NOSYSTEM=1", "LC_ALL=C"}
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper-free fixture %v: %v (%s)", args, err, stderr.String())
	}
	return out.String()
}
func preparedFixture(t *testing.T, root string, r *GitRunner) *metadataView {
	t.Helper()
	v, err := prepareMetadata(context.Background(), root, r, newMetadataBudget(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	})
	return v
}

var metadataStatus = []string{"status", "--porcelain=v1", "-z", "--ignore-submodules=all"}

func TestMetadata_StatusDifferential(t *testing.T) {
	for _, name := range []string{"clean", "staged", "unstaged", "deletion", "rename", "copy", "untracked", "control", "packed", "ignore", "attributes", "crlf-clean", "crlf-dirty", "lf-input", "ident", "encoding", "untracked-all", "filemode-off", "index-v4"} {
		t.Run(name, func(t *testing.T) {
			root, r := metadataFixture(t, false)
			switch name {
			case "staged":
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\n")
				fixtureCommand(t, r, root, "add", "tracked.txt")
			case "unstaged":
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\n")
			case "deletion":
				if err := os.Remove(filepath.Join(root, "tracked.txt")); err != nil {
					t.Fatal(err)
				}
			case "rename":
				fixtureCommand(t, r, root, "mv", "tracked.txt", "renamed.txt")
			case "copy":
				fixtureCommand(t, r, root, "config", "status.renames", "copies")
				metadataWrite(t, filepath.Join(root, "copy.txt"), "AAAAAAAA\n")
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\n")
				fixtureCommand(t, r, root, "add", ".")
			case "untracked", "untracked-all":
				metadataWrite(t, filepath.Join(root, "nested", "deeper", "one.txt"), "1\n")
				metadataWrite(t, filepath.Join(root, "nested", "two.txt"), "2\n")
				metadataWrite(t, filepath.Join(root, "new.txt"), "3\n")
				if name == "untracked-all" {
					fixtureCommand(t, r, root, "config", "status.showUntrackedFiles", "all")
				}
			case "control":
				for _, n := range []string{"line\nname", "tab\tname", "esc\x1bname"} {
					metadataWrite(t, filepath.Join(root, n), "data\n")
				}
			case "packed":
				fixtureCommand(t, r, root, "pack-refs", "--all")
				fixtureCommand(t, r, root, "-c", "pack.writeReverseIndex=false", "repack", "-a", "-d")
			case "ignore":
				metadataWrite(t, filepath.Join(root, ".gitignore"), "ignored\n")
				metadataWrite(t, filepath.Join(root, "ignored"), "data\n")
			case "attributes", "crlf-clean", "crlf-dirty", "lf-input":
				attr := "tracked.txt text eol=crlf\n"
				data := "AAAAAAAA\r\n"
				if name == "lf-input" {
					attr = "tracked.txt text eol=lf\n"
					data = "AAAAAAAA\n"
					fixtureCommand(t, r, root, "config", "core.autocrlf", "input")
				}
				metadataWrite(t, filepath.Join(root, ".gitattributes"), attr)
				metadataWrite(t, filepath.Join(root, "tracked.txt"), data)
				if name == "attributes" {
					metadataWrite(t, filepath.Join(root, ".git", "info", "attributes"), attr)
					metadataWrite(t, filepath.Join(root, ".git", "info", "exclude"), "info-ignored\n")
					metadataWrite(t, filepath.Join(root, "info-ignored"), "data\n")
				}
				fixtureCommand(t, r, root, "add", ".")
				fixtureCommand(t, r, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "conversion")
				if name == "crlf-dirty" {
					metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\r\n")
				}
				stamp := time.Unix(1500000000, 123456789)
				if err := os.Chtimes(filepath.Join(root, "tracked.txt"), stamp, stamp); err != nil {
					t.Fatal(err)
				}
			case "ident":
				metadataWrite(t, filepath.Join(root, ".gitattributes"), "tracked.txt ident\n")
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "$Id$\n")
				fixtureCommand(t, r, root, "add", ".")
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "$Id: abcdef $\n")
			case "encoding":
				metadataWrite(t, filepath.Join(root, ".gitattributes"), "tracked.txt working-tree-encoding=UTF-16LE\n")
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "A\x00A\x00\n\x00")
				fixtureCommand(t, r, root, "add", ".")
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "B\x00B\x00\n\x00")
			case "filemode-off":
				fixtureCommand(t, r, root, "config", "core.filemode", "false")
				if err := os.Chmod(filepath.Join(root, "tracked.txt"), 0700); err != nil {
					t.Fatal(err)
				}
			case "index-v4":
				fixtureCommand(t, r, root, "update-index", "--index-version=4")
			}
			native := fixtureCommand(t, r, root, metadataStatus...)
			v := preparedFixture(t, root, r)
			out, err := v.Run(context.Background(), root, metadataStatus...)
			if err != nil || out != native {
				t.Fatalf("native %q view %q error %v", native, out, err)
			}
			if err := v.verify(); err != nil {
				t.Fatal(err)
			}
			t.Logf("bytes=%d entries=%d descriptor accounting=%d children=%d", v.budget.bytes, v.budget.entries, v.budget.descriptors, v.budget.commands)
			if name == "untracked" && out != "?? nested/\x00?? new.txt\x00" {
				t.Fatal(out)
			}
			if name == "copy" && out != "C  copy.txt\x00tracked.txt\x00M  tracked.txt\x00" {
				t.Fatalf("copy oracle sensitivity: %q", out)
			}
			if (name == "crlf-clean" || name == "lf-input") && out != "" {
				t.Fatalf("clean conversion oracle: %q", out)
			}
		})
	}
}

func TestMetadata_RacyIndexNegativeControl(t *testing.T) {
	root, r := metadataFixture(t, false)
	fixtureCommand(t, r, root, "config", "core.trustctime", "false")
	fixtureCommand(t, r, root, "config", "core.checkstat", "minimal")
	stamp := time.Unix(1500000000, 123456789)
	file := filepath.Join(root, "tracked.txt")
	index := filepath.Join(root, ".git", "index")
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	fixtureCommand(t, r, root, "add", "tracked.txt")
	if err := os.Chtimes(index, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	metadataWrite(t, file, "BBBBBBBB\n")
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	native := fixtureCommand(t, r, root, metadataStatus...)
	if native != " M tracked.txt\x00" {
		t.Fatalf("racy sensitivity not established: %q", native)
	}
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	v := preparedFixture(t, root, r)
	copyPath := filepath.Join(v.dir, "index")
	copyBytes, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.Stat(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, copyBytes) || source.Size() != copied.Size() || source.Mode().Perm() != copied.Mode().Perm() || !source.ModTime().Equal(copied.ModTime()) || source.ModTime().Nanosecond() != 123456789 {
		t.Fatal("index identity not preserved")
	}
	correct, err := v.Run(context.Background(), root, metadataStatus...)
	if err != nil || correct != native {
		t.Fatal(correct, err)
	}
	// Deliberately reproduce the rejected construction only in the owned view.
	fresh := time.Now()
	if err := os.Chtimes(copyPath, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Run(context.Background(), root, metadataStatus...); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal("changed copied timestamp was admitted", err)
	}
	// The negative control deliberately bypasses only copied-index fidelity
	// admission, retaining the generated policy/private objects/environment.
	naive, err := v.runner.runControlled(context.Background(), v, root, metadataStatus...)
	if err != nil || naive != "" {
		t.Fatalf("negative control must be false-clean: %q %v", naive, err)
	}
	if err := v.verify(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(index)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("original index changed", err)
	}
	t.Logf("native=%q corrected=%q naive=%q index mtime=%s", native, correct, naive, source.ModTime().Format(time.RFC3339Nano))
}

func TestMetadata_BranchAndApplicability(t *testing.T) {
	for _, name := range []string{"normal", "unborn", "detached", "subdirectory", "alias"} {
		t.Run(name, func(t *testing.T) {
			root, r := metadataFixture(t, name == "unborn")
			selected := root
			if name == "detached" {
				fixtureCommand(t, r, root, "checkout", "--detach")
			}
			if name == "subdirectory" {
				selected = filepath.Join(root, "sub")
				if err := os.Mkdir(selected, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if name == "alias" {
				selected = filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, selected); err != nil {
					t.Fatal(err)
				}
			}
			s, err := CollectSnapshot(context.Background(), selected)
			if err != nil {
				t.Fatal(s, err)
			}
			want := scanstate.CheckStatusCompleted
			branch := scanstate.GitBranchNormal
			if name == "unborn" {
				branch = scanstate.GitBranchUnborn
			}
			if name == "detached" {
				branch = scanstate.GitBranchDetached
			}
			if name == "subdirectory" {
				want = scanstate.CheckStatusNotApplicable
			}
			if s.Status != want || s.BranchState != branch || s.Availability != scanstate.GitAvailable {
				t.Fatal(s)
			}
		})
	}
}

func TestMetadata_Refusals(t *testing.T) {
	for _, name := range []string{"unknown-config", "include", "includeIf", "filter-required", "gitfile", "commondir", "config-symlink", "index-fifo", "sparse", "split", "assume", "skip", "gitlink", "alternates", "promisor-marker", "unknown-sidecar", "replacement", "shallow", "unknown-extension", "corrupt-index"} {
		t.Run(name, func(t *testing.T) {
			root, r := metadataFixture(t, false)
			gd := filepath.Join(root, ".git")
			switch name {
			case "unknown-config", "include", "includeIf", "filter-required", "sparse", "unknown-extension":
				setting := map[string]string{"unknown-config": "[core]\nunknownSemantic=true\n", "include": "[include]\npath=../invalid.cfg\n", "includeIf": "[includeIf \"onbranch:main\"]\npath=../invalid.cfg\n", "filter-required": "[filter \"fixture\"]\nrequired=true\n", "sparse": "[core]\nsparseCheckout=true\n", "unknown-extension": "[extensions]\nunknown=true\n"}[name]
				metadataWrite(t, filepath.Join(root, "invalid.cfg"), "invalid syntax\n")
				f, err := os.OpenFile(filepath.Join(gd, "config"), os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteString(setting); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			case "gitfile":
				if err := os.Rename(gd, filepath.Join(t.TempDir(), "external")); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, gd, "gitdir: ../external\n")
			case "commondir":
				metadataWrite(t, filepath.Join(gd, "commondir"), "../external\n")
			case "config-symlink":
				path := filepath.Join(gd, "config")
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("config.original", path); err != nil {
					t.Fatal(err)
				}
			case "index-fifo":
				path := filepath.Join(gd, "index")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "split":
				fixtureCommand(t, r, root, "update-index", "--split-index")
			case "assume":
				fixtureCommand(t, r, root, "update-index", "--assume-unchanged", "tracked.txt")
			case "skip":
				fixtureCommand(t, r, root, "update-index", "--skip-worktree", "tracked.txt")
			case "gitlink":
				oid := strings.TrimSpace(fixtureCommand(t, r, root, "rev-parse", "HEAD"))
				fixtureCommand(t, r, root, "update-index", "--add", "--cacheinfo", "160000,"+oid+",module")
			case "alternates":
				metadataWrite(t, filepath.Join(gd, "objects", "info", "alternates"), "../other\n")
			case "promisor-marker":
				metadataWrite(t, filepath.Join(gd, "objects", "pack", "pack-"+strings.Repeat("a", 40)+".promisor"), "")
			case "unknown-sidecar":
				metadataWrite(t, filepath.Join(gd, "objects", "pack", "pack-"+strings.Repeat("a", 40)+".rev"), "unused\n")
			case "replacement":
				metadataWrite(t, filepath.Join(gd, "refs", "replace", strings.Repeat("a", 40)), strings.Repeat("b", 40)+"\n")
			case "shallow":
				metadataWrite(t, filepath.Join(gd, "shallow"), strings.Repeat("a", 40)+"\n")
			case "corrupt-index":
				metadataWrite(t, filepath.Join(gd, "index"), "invalid index\n")
			}
			s, err := CollectSnapshot(context.Background(), root)
			if !errors.Is(err, ErrUnsafeGitMetadata) || s.Status != scanstate.CheckStatusPartial || s.Availability != scanstate.GitAvailable || s.ModifiedCount != 0 || s.UntrackedCount != 0 {
				t.Fatal(s, err)
			}
			if strings.Contains(err.Error(), "invalid.cfg") {
				t.Fatal("raw path leaked")
			}
		})
	}
}

func TestMetadata_AmbientIgnoreNegativeControl(t *testing.T) {
	root, r := metadataFixture(t, false)
	metadataWrite(t, filepath.Join(root, "ambient-ignored"), "data\n")
	metadataWrite(t, filepath.Join(os.Getenv("HOME"), ".config", "git", "ignore"), "ambient-ignored\n")
	t.Setenv("XDG_CONFIG_HOME", "")
	original := fixtureCommand(t, r, root, metadataStatus...)
	if original != "" {
		t.Fatal(original)
	}
	_, err := prepareMetadata(context.Background(), root, r, newMetadataBudget(context.Background()))
	if !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal(err)
	}
	// Show the incompatible HOME-only construction without bypassing production
	// admission: run trusted native fixture Git under an empty synthetic HOME.
	t.Setenv("HOME", t.TempDir())
	without := fixtureCommand(t, r, root, metadataStatus...)
	if without != "?? ambient-ignored\x00" {
		t.Fatalf("ambient sensitivity not established: %q", without)
	}
	t.Logf("original=%q private HOME alone=%q; production refuses", original, without)
}

func TestMetadata_IsolationMutationBudgetsCleanup(t *testing.T) {
	root, r := metadataFixture(t, false)
	for _, n := range []string{"GIT_DIR", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_ATTR_SOURCE"} {
		t.Setenv(n, "untrusted-ambient-value")
	}
	v := preparedFixture(t, root, r)
	allocation := v.allocation
	live, err := os.ReadFile(filepath.Join(v.dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(live), "user.") || strings.Contains(string(live), "include") || strings.Contains(string(live), "filter") {
		t.Fatal("original policy became live")
	}
	metadataWrite(t, filepath.Join(root, ".git", "config"), "[core]\nrepositoryformatversion=0\n[include]\npath=invalid.cfg\n")
	out, err := v.Run(context.Background(), root, metadataStatus...)
	if err != nil || out != "" {
		t.Fatal("copied view affected by original config mutation", out, err)
	}
	if err := v.verify(); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal("source mutation undetected", err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(allocation); !os.IsNotExist(err) {
		t.Fatal("allocation remains", err)
	}
	if _, err := v.Run(context.Background(), root, metadataStatus...); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal("closed capability used", err)
	}
	root, r = metadataFixture(t, false)
	for _, kind := range []string{"bytes", "entries", "descriptors", "deadline", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := newMetadataBudget(ctx)
			switch kind {
			case "bytes":
				b.maxBytes = 16
			case "entries":
				b.maxEntries = 1
			case "descriptors":
				b.maxDescriptors = 16
			case "deadline":
				b.deadline = time.Now().Add(-time.Second)
			case "cancel":
				cancel()
			}
			v, err := prepareMetadata(ctx, root, r, b)
			if v != nil || (kind != "cancel" && !errors.Is(err, ErrUnsafeGitMetadata)) || (kind == "cancel" && !errors.Is(err, context.Canceled)) {
				t.Fatal(v, err)
			}
		})
	}
}

func TestMetadata_ConfigAndIndexAdmission(t *testing.T) {
	for _, records := range []string{"filter.fixture.clean\nunreviewed\x00", "include.path\ninvalid\x00", "core.worktree\nelsewhere\x00", "core.autocrlf\ninvalid\x00", "remote.origin.promisor\ntrue\x00", "credential.helper\nunreviewed\x00", "core.fsmonitor\nunreviewed\x00", "core.attributesfile\nelsewhere\x00", "core.excludesfile\nelsewhere\x00", "core.filemode\n2\x00", "status.renamelimit\n100001\x00", "extensions.objectformat\nsha256\x00"} {
		if _, err := projectConfig(records); !errors.Is(err, ErrUnsafeGitMetadata) {
			t.Fatal(records, err)
		}
	}
	config, err := projectConfig("core.filemode\nyes\x00core.trustctime\x00core.ignorecase\n\x00core.checkstat\nminimal\x00status.renames\ncopies\x00status.renamelimit\n000123\x00user.name\nnot live\x00remote.origin.url\nnot live\x00alias.fixture\nnot live\x00")
	if err != nil || !strings.Contains(config, "filemode = true") || !strings.Contains(config, "trustctime = true") || !strings.Contains(config, "ignorecase = false") || !strings.Contains(config, "renamelimit = 123") || strings.Contains(config, "not live") {
		t.Fatal(config, err)
	}
	// Unknown optional extensions must refuse even though Git would ignore them.
	index := make([]byte, 12)
	copy(index, "DIRC")
	binary.BigEndian.PutUint32(index[4:8], 2)
	index = append(index, []byte("ZZZZ\x00\x00\x00\x00")...)
	sum := sha1.Sum(index)
	index = append(index, sum[:]...)
	if err := admitIndexEnvelope(index); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal(err)
	}
}

func TestMetadata_AmbientPolicyAndCancellation(t *testing.T) {
	for _, name := range []string{"home-attributes", "xdg-ignore", "xdg-attributes", "system-source", "unreadable-source"} {
		t.Run(name, func(t *testing.T) {
			root, r := metadataFixture(t, false)
			path := filepath.Join(os.Getenv("HOME"), ".config", "git", "attributes")
			if strings.HasPrefix(name, "xdg-") {
				path = filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git", strings.TrimPrefix(name, "xdg-"))
			}
			if name == "system-source" || name == "unreadable-source" {
				path = filepath.Join(t.TempDir(), "gitattributes")
			}
			metadataWrite(t, path, "* text\n")
			if name == "unreadable-source" {
				if err := os.Chmod(path, 0000); err != nil {
					t.Fatal(err)
				}
			}
			if name == "system-source" || name == "unreadable-source" {
				b := newMetadataBudget(context.Background())
				s := &metadataSource{budget: b}
				defer s.close()
				if err := s.absentAmbient(path); !errors.Is(err, ErrUnsafeGitMetadata) {
					t.Fatal(err)
				}
			} else {
				if _, err := prepareMetadata(context.Background(), root, r, newMetadataBudget(context.Background())); !errors.Is(err, ErrUnsafeGitMetadata) {
					t.Fatal(err)
				}
			}
		})
	}
	root, r := metadataFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	v, err := prepareMetadata(ctx, root, r, newMetadataBudget(ctx))
	if err != nil {
		t.Fatal(err)
	}
	pins := append([]*os.File(nil), v.source.dirs...)
	allocation := v.allocation
	cancel()
	if _, err := v.Run(ctx, root, metadataStatus...); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := v.verify(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range pins {
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("descriptor survived", err)
		}
	}
	if _, err := os.Lstat(allocation); !os.IsNotExist(err) {
		t.Fatal("cancelled allocation survived", err)
	}
}

func TestMetadata_ObjectMutationAndRequiredCorruption(t *testing.T) {
	for _, kind := range []string{"missing-commit", "corrupt-commit", "missing-tree", "corrupt-tree"} {
		t.Run(kind, func(t *testing.T) {
			root, r := metadataFixture(t, false)
			revision := "HEAD"
			if strings.HasSuffix(kind, "tree") {
				revision = "HEAD^{tree}"
			}
			oid := strings.TrimSpace(fixtureCommand(t, r, root, "rev-parse", "--verify", revision))
			path := filepath.Join(root, ".git", "objects", oid[:2], oid[2:])
			if strings.HasPrefix(kind, "missing") {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, path, "corrupt ordinary object\n")
			}
			s, err := CollectSnapshot(context.Background(), root)
			if err == nil || s.Status != scanstate.CheckStatusPartial || s.Availability != scanstate.GitAvailable || s.ModifiedCount != 0 || s.UntrackedCount != 0 {
				t.Fatal(s, err)
			}
		})
	}
	root, r := metadataFixture(t, false)
	v := preparedFixture(t, root, r)
	// Creating an alternate after copying cannot expand the view's object graph.
	metadataWrite(t, filepath.Join(root, ".git", "objects", "info", "alternates"), "../unavailable\n")
	if _, err := os.Lstat(filepath.Join(v.dir, "objects", "info", "alternates")); !os.IsNotExist(err) {
		t.Fatal("alternate borrowed", err)
	}
	out, err := v.Run(context.Background(), root, metadataStatus...)
	if err != nil || out != "" {
		t.Fatal(out, err)
	}
	if err := v.verify(); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal("object source mutation undetected", err)
	}
}

func TestMetadata_SubdirectoryExecutableRefusedBeforeChild(t *testing.T) {
	root, _ := metadataFixture(t, false)
	sub := filepath.Join(root, "sub")
	bin := filepath.Join(root, "bin")
	for _, p := range []string{sub, bin} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(bin, "git")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 91\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	r, err := NewGitRunner(sub)
	if err != nil {
		t.Fatal(err)
	}
	b := newMetadataBudget(context.Background())
	_, err = prepareMetadata(context.Background(), sub, r, b)
	if !errors.Is(err, ErrUnsafeGitMetadata) || b.commands != 0 {
		t.Fatal("repository-owned executable reached child startup", err, b.commands)
	}
}
