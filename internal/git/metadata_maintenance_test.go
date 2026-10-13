//go:build darwin || linux

package git

import (
	"bytes"
	"context"
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

// Every original Git invocation in this file is confined to a fresh helper-free
// fixture. No remote, executable config, inherited user policy or hook is used.
func maintenanceFixture(t *testing.T, cruft bool) (string, *GitRunner) {
	t.Helper()
	root, r := metadataFixture(t, false)
	fixtureCommand(t, r, root, "-c", "pack.writeReverseIndex=true", "repack", "-d")
	metadataWrite(t, filepath.Join(root, "second.txt"), "second pack\n")
	fixtureCommand(t, r, root, "add", ".")
	fixtureCommand(t, r, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "second")
	fixtureCommand(t, r, root, "-c", "pack.writeReverseIndex=true", "repack", "-d")
	packs, _ := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", "*.pack"))
	if len(packs) < 2 {
		t.Fatalf("multiple ordinary packs not established: %v", packs)
	}
	if cruft {
		// An unreferenced commit and blob, produced before recovery/maintenance.
		fixtureCommand(t, r, root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "dangling")
		metadataWrite(t, filepath.Join(root, "recovery.txt"), "dangling recovery bytes\n")
		fixtureCommand(t, r, root, "hash-object", "-w", "recovery.txt")
		if err := os.Remove(filepath.Join(root, "recovery.txt")); err != nil {
			t.Fatal(err)
		}
		fixtureCommand(t, r, root, "fsck", "--lost-found")
		fixtureCommand(t, r, root, "-c", "pack.writeReverseIndex=true", "repack", "--cruft", "-d")
		mtimes, _ := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", "*.mtimes"))
		if len(mtimes) == 0 {
			t.Fatal("cruft sidecar not generated")
		}
		for _, kind := range []string{"commit", "other"} {
			files, _ := filepath.Glob(filepath.Join(root, ".git", "lost-found", kind, "*"))
			if len(files) == 0 {
				t.Fatalf("lost-found %s not populated", kind)
			}
		}
	}
	fixtureCommand(t, r, root, "pack-refs", "--all")
	fixtureCommand(t, r, root, "branch", "loose")
	fixtureCommand(t, r, root, "multi-pack-index", "write")
	revs, _ := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", "*.rev"))
	if len(revs) == 0 {
		t.Fatal("reverse indexes not generated")
	}
	t.Logf("installed %s packs=%d reverse indexes=%d cruft=%v", strings.TrimSpace(fixtureCommand(t, r, root, "--version")), len(packs), len(revs), cruft)
	return root, r
}

func maintenanceCompare(t *testing.T, root string, r *GitRunner, v *metadataView) string {
	t.Helper()
	queries := [][]string{{"rev-parse", "--show-toplevel"}, {"symbolic-ref", "--quiet", "HEAD"}, {"show-ref", "--verify", "--quiet", "refs/heads/main"}, {"rev-parse", "--verify", "HEAD^{commit}"}, metadataStatus}
	var status string
	for _, q := range queries {
		native := fixtureCommand(t, r, root, q...)
		out, err := v.Run(context.Background(), root, q...)
		if err != nil || out != native {
			t.Fatalf("%v: original=%q controlled=%q error=%v", q, native, out, err)
		}
		if q[0] == "status" {
			status = out
		}
	}
	if err := v.verify(); err != nil {
		t.Fatal(err)
	}
	t.Logf("exact five-query comparison passed; status=%q bytes=%d children=%d", status, v.budget.bytes, v.budget.commands)
	return status
}

func TestMaintenance_Differential(t *testing.T) {
	for _, state := range []string{"clean", "staged", "unstaged", "untracked", "deleted", "renamed", "racy"} {
		t.Run(state, func(t *testing.T) {
			root, r := maintenanceFixture(t, true)
			switch state {
			case "staged":
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\n")
				fixtureCommand(t, r, root, "add", "tracked.txt")
			case "unstaged":
				metadataWrite(t, filepath.Join(root, "tracked.txt"), "BBBBBBBB\n")
			case "untracked":
				metadataWrite(t, filepath.Join(root, "nested", "new.txt"), "new\n")
			case "deleted":
				if err := os.Remove(filepath.Join(root, "tracked.txt")); err != nil {
					t.Fatal(err)
				}
			case "renamed":
				fixtureCommand(t, r, root, "mv", "tracked.txt", "renamed.txt")
			case "racy":
				fixtureCommand(t, r, root, "config", "core.trustctime", "false")
				fixtureCommand(t, r, root, "config", "core.checkstat", "minimal")
				stamp := time.Unix(1500000000, 123456789)
				file := filepath.Join(root, "tracked.txt")
				if err := os.Chtimes(file, stamp, stamp); err != nil {
					t.Fatal(err)
				}
				fixtureCommand(t, r, root, "add", "tracked.txt")
				if err := os.Chtimes(filepath.Join(root, ".git", "index"), stamp, stamp); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, file, "BBBBBBBB\n")
				if err := os.Chtimes(file, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			v := preparedFixture(t, root, r)
			for _, pattern := range []string{"multi-pack-index", "*.rev", "*.mtimes", "*.pack", "*.idx"} {
				paths, _ := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", pattern))
				if len(paths) == 0 {
					t.Fatal("fixture lacks", pattern)
				}
				for _, p := range paths {
					a, e := os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
					b, e := os.ReadFile(filepath.Join(v.dir, "objects", "pack", filepath.Base(p)))
					if e != nil || !bytes.Equal(a, b) {
						t.Fatal("sidecar/object bytes not preserved", p, e)
					}
				}
			}
			if _, err := os.Stat(filepath.Join(v.dir, "lost-found")); !os.IsNotExist(err) {
				t.Fatal("recovery namespace became live", err)
			}
			status := maintenanceCompare(t, root, r, v)
			expected := map[string]string{"clean": "", "staged": "M  tracked.txt\x00", "unstaged": " M tracked.txt\x00", "untracked": "?? nested/\x00", "deleted": " D tracked.txt\x00", "renamed": "R  renamed.txt\x00tracked.txt\x00", "racy": " M tracked.txt\x00"}
			if status != expected[state] {
				t.Fatalf("oracle sensitivity: got %q expected %q", status, expected[state])
			}
		})
	}
}

func TestMaintenance_OptionalAbsenceAndOmission(t *testing.T) {
	for _, name := range []string{"multiple-packs", "empty-lost-found", "empty-recovery-dirs", "no-midx", "no-rev", "no-mtimes", "omit-copied-sidecars"} {
		t.Run(name, func(t *testing.T) {
			root, r := maintenanceFixture(t, name != "multiple-packs" && name != "empty-lost-found" && name != "empty-recovery-dirs")
			switch name {
			case "empty-lost-found":
				if err := os.Mkdir(filepath.Join(root, ".git", "lost-found"), 0700); err != nil {
					t.Fatal(err)
				}
			case "empty-recovery-dirs":
				for _, k := range []string{"commit", "other"} {
					if err := os.MkdirAll(filepath.Join(root, ".git", "lost-found", k), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "no-midx", "no-rev", "no-mtimes":
				pattern := map[string]string{"no-midx": "multi-pack-index", "no-rev": "*.rev", "no-mtimes": "*.mtimes"}[name]
				paths, _ := filepath.Glob(filepath.Join(root, ".git", "objects", "pack", pattern))
				if len(paths) == 0 {
					t.Fatal("absence control not sensitive")
				}
				for _, p := range paths {
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
				}
			}
			v := preparedFixture(t, root, r)
			if name == "omit-copied-sidecars" {
				// Experimental omission only. Production retains sidecars to preserve
				// error behavior too; the corrupt-MIDX control below proves why.
				for _, pattern := range []string{"multi-pack-index", "*.rev", "*.mtimes"} {
					paths, _ := filepath.Glob(filepath.Join(v.dir, "objects", "pack", pattern))
					for _, p := range paths {
						if err := os.Remove(p); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			maintenanceCompare(t, root, r, v)
		})
	}
}

func maintenanceOriginalResult(t *testing.T, root string, r *GitRunner, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.gitPath, append([]string{"--no-pager", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "XDG_CONFIG_HOME=" + os.Getenv("XDG_CONFIG_HOME"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1", "GIT_ATTR_NOSYSTEM=1", "LC_ALL=C"}
	var out, diag bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diag
	err := cmd.Run()
	code := 0
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	t.Logf("helper-free original query %v exit=%d stdout=%q stderr=%q", args, code, out.String(), diag.String())
	return out.String(), code
}

func TestMaintenance_MalformedAndRequiredObjects(t *testing.T) {
	for _, name := range []string{"midx-header", "midx-body", "rev-header", "mtimes-header", "rev-body", "mtimes-body", "missing-pack", "missing-index", "pack-corrupt", "index-corrupt", "required-cruft-commit"} {
		t.Run(name, func(t *testing.T) {
			root, r := maintenanceFixture(t, true)
			packdir := filepath.Join(root, ".git", "objects", "pack")
			switch name {
			case "midx-header":
				p := filepath.Join(packdir, "multi-pack-index")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				copy(data[:4], "BAD!")
				metadataWrite(t, p, string(data))
			case "midx-body":
				p := filepath.Join(packdir, "multi-pack-index")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				// Keep the reviewed envelope; corrupt the required PNAM chunk ID.
				copy(data[12:16], "LOFF")
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "rev-header", "mtimes-header":
				ext := "rev"
				if name == "mtimes-header" {
					ext = "mtimes"
				}
				paths, _ := filepath.Glob(filepath.Join(packdir, "*."+ext))
				if len(paths) == 0 {
					t.Fatal("missing sidecar")
				}
				if err := os.Chmod(paths[0], 0600); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, paths[0], "BAD! invalid maintenance\n")
			case "rev-body", "mtimes-body":
				ext := "rev"
				if name == "mtimes-body" {
					ext = "mtimes"
				}
				paths, _ := filepath.Glob(filepath.Join(packdir, "*."+ext))
				if len(paths) == 0 {
					t.Fatal("missing sidecar")
				}
				data, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 0xff
				if err := os.Chmod(paths[0], 0600); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, paths[0], string(data))
				maintenanceCompare(t, root, r, preparedFixture(t, root, r))
				return
			case "missing-pack", "missing-index", "pack-corrupt", "index-corrupt":
				// Corrupt all packs/indexes so another duplicate cannot mask failure.
				ext := "pack"
				if name == "missing-index" || name == "index-corrupt" {
					ext = "idx"
				}
				paths, _ := filepath.Glob(filepath.Join(packdir, "*."+ext))
				for _, p := range paths {
					if strings.HasPrefix(name, "missing") {
						if err := os.Remove(p); err != nil {
							t.Fatal(err)
						}
					} else {
						if err := os.Chmod(p, 0600); err != nil {
							t.Fatal(err)
						}
						metadataWrite(t, p, "invalid required object data\n")
					}
				}
			case "required-cruft-commit":
				// A recovered dangling commit is now HEAD and must remain available in
				// the copied cruft pack, even without its optional timestamps.
				commits, _ := filepath.Glob(filepath.Join(root, ".git", "lost-found", "commit", "*"))
				if len(commits) == 0 {
					t.Fatal("missing dangling commit")
				}
				metadataWrite(t, filepath.Join(root, ".git", "refs", "heads", "main"), filepath.Base(commits[0])+"\n")
				paths, _ := filepath.Glob(filepath.Join(packdir, "*.mtimes"))
				for _, p := range paths {
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
				}
				maintenanceCompare(t, root, r, preparedFixture(t, root, r))
				return
			}
			_, nativeExit := maintenanceOriginalResult(t, root, r, metadataStatus...)
			snapshot, err := CollectSnapshot(context.Background(), root)
			if err == nil || snapshot.Status != scanstate.CheckStatusPartial || snapshot.ModifiedCount != 0 || snapshot.UntrackedCount != 0 {
				t.Fatalf("invalid metadata manufactured status: %+v %v", snapshot, err)
			}
			if name == "midx-header" || name == "midx-body" || name == "pack-corrupt" || name == "index-corrupt" {
				if nativeExit == 0 {
					t.Fatal("required corruption oracle did not fail")
				}
			}
			t.Logf("candidate visibly partial, original status exit=%d candidate error=%v", nativeExit, err)
		})
	}
}

func TestMaintenance_CorruptMIDXOmissionNegativeControl(t *testing.T) {
	root, r := maintenanceFixture(t, true)
	v := preparedFixture(t, root, r)
	// Same corrupt known envelope in the source and already checked private
	// copy. This deliberately bypasses production preparation only in the test.
	for _, p := range []string{filepath.Join(root, ".git", "objects", "pack", "multi-pack-index"), filepath.Join(v.dir, "objects", "pack", "multi-pack-index")} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		copy(data[12:16], "LOFF")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, code := maintenanceOriginalResult(t, root, r, metadataStatus...)
	if code == 0 {
		t.Fatal("malformed MIDX sensitivity absent")
	}
	if _, err := v.Run(context.Background(), root, metadataStatus...); err == nil {
		t.Fatal("copied malformed MIDX error concealed")
	}
	if err := os.Remove(filepath.Join(v.dir, "objects", "pack", "multi-pack-index")); err != nil {
		t.Fatal(err)
	}
	out, err := v.Run(context.Background(), root, metadataStatus...)
	if err != nil || out != "" {
		t.Fatalf("omission negative control: status=%q err=%v", out, err)
	}
	t.Log("omitting malformed MIDX manufactured clean status; production retains the bytes")
}

func TestMaintenance_TypesNamesMutationAndBudgets(t *testing.T) {
	for _, name := range []string{"sidecar-link", "sidecar-fifo", "sidecar-directory", "unknown-suffix", "orphan-rev", "orphan-mtimes", "midx-chain", "midx-version", "midx-hash", "midx-chunk", "midx-path", "midx-missing-pair", "midx-base", "midx-offset", "midx-count", "midx-truncated", "unknown-pack-name", "lost-root-link", "lost-kind-link", "lost-file-link", "lost-fifo", "lost-subdirectory", "lost-unknown-kind", "lost-unknown-name", "lost-bytes", "sidecar-bytes", "entries", "descriptors", "mutation-sidecar", "mutation-lost-file", "mutation-empty-lost"} {
		t.Run(name, func(t *testing.T) {
			root, r := maintenanceFixture(t, true)
			packdir := filepath.Join(root, ".git", "objects", "pack")
			lost := filepath.Join(root, ".git", "lost-found")
			revs, _ := filepath.Glob(filepath.Join(packdir, "*.rev"))
			sidecar := revs[0]
			target := filepath.Join(lost, "other", strings.Repeat("a", 40))
			budget := newMetadataBudget(context.Background())
			switch name {
			case "sidecar-link", "sidecar-fifo", "sidecar-directory":
				if err := os.Remove(sidecar); err != nil {
					t.Fatal(err)
				}
				var err error
				if name == "sidecar-link" {
					err = os.Symlink(filepath.Join(root, "tracked.txt"), sidecar)
				} else if name == "sidecar-fifo" {
					err = unix.Mkfifo(sidecar, 0600)
				} else {
					err = os.Mkdir(sidecar, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "unknown-suffix":
				metadataWrite(t, filepath.Join(packdir, "pack-"+strings.Repeat("a", 40)+".bitmap"), "")
			case "orphan-rev", "orphan-mtimes":
				ext := strings.TrimPrefix(name, "orphan-")
				metadataWrite(t, filepath.Join(packdir, "pack-"+strings.Repeat("a", 40)+"."+ext), "RIDX\x00\x00\x00\x01\x00\x00\x00\x01")
			case "midx-chain":
				if err := os.Mkdir(filepath.Join(packdir, "multi-pack-index.d"), 0700); err != nil {
					t.Fatal(err)
				}
			case "midx-version", "midx-hash", "midx-chunk":
				p := filepath.Join(packdir, "multi-pack-index")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if name == "midx-version" {
					data[4] = 2
				} else if name == "midx-hash" {
					data[5] = 2
				} else {
					copy(data[12:16], "ZZZZ")
				}
				if err := os.WriteFile(p, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "midx-path", "midx-missing-pair", "midx-base", "midx-offset", "midx-count", "midx-truncated":
				p := filepath.Join(packdir, "multi-pack-index")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				off := int(binary.BigEndian.Uint64(data[16:24]))
				switch name {
				case "midx-path":
					copy(data[off:off+5], "../x/")
				case "midx-missing-pair":
					for i := off + 5; i < off+45; i++ {
						data[i] = '0'
					}
				case "midx-base":
					data[7] = 1
				case "midx-offset":
					binary.BigEndian.PutUint64(data[16:24], ^uint64(0))
				case "midx-count":
					binary.BigEndian.PutUint32(data[8:12], metadataEntries+1)
				case "midx-truncated":
					data = data[:20]
				}
				metadataWrite(t, p, string(data))
			case "unknown-pack-name":
				metadataWrite(t, filepath.Join(packdir, "unreviewed.rev"), "")
			case "lost-root-link", "lost-kind-link":
				p := lost
				if name == "lost-kind-link" {
					p = filepath.Join(lost, "other")
				}
				// Move only disposable fixture data, preserving it beside the test root.
				if err := os.Rename(p, p+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+"-saved", p); err != nil {
					t.Fatal(err)
				}
			case "lost-file-link":
				if err := os.Symlink(filepath.Join(root, "tracked.txt"), target); err != nil {
					t.Fatal(err)
				}
			case "lost-fifo":
				if err := unix.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "lost-subdirectory":
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "lost-unknown-kind":
				if err := os.Mkdir(filepath.Join(lost, "unknown"), 0700); err != nil {
					t.Fatal(err)
				}
			case "lost-unknown-name":
				metadataWrite(t, filepath.Join(lost, "other", "not-an-object"), "")
			case "lost-bytes", "sidecar-bytes":
				p := target
				if name == "sidecar-bytes" {
					p = sidecar
				}
				if name == "sidecar-bytes" {
					if err := os.Chmod(p, 0600); err != nil {
						t.Fatal(err)
					}
				}
				f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(f.Truncate(64<<20+1), f.Close()); err != nil {
					t.Fatal(err)
				}
			case "entries":
				budget.maxEntries = 10
			case "descriptors":
				budget.maxDescriptors = 20
			case "mutation-sidecar", "mutation-lost-file", "mutation-empty-lost":
				if name == "mutation-empty-lost" {
					for _, kind := range []string{"commit", "other"} {
						paths, _ := filepath.Glob(filepath.Join(lost, kind, "*"))
						for _, p := range paths {
							if err := os.Remove(p); err != nil {
								t.Fatal(err)
							}
						}
						if err := os.Remove(filepath.Join(lost, kind)); err != nil {
							t.Fatal(err)
						}
					}
				}
				v := preparedFixture(t, root, r)
				if name == "mutation-sidecar" {
					if err := os.Chmod(sidecar, 0600); err != nil {
						t.Fatal(err)
					}
					metadataWrite(t, sidecar, "mutated original")
				}
				if name == "mutation-lost-file" {
					paths, _ := filepath.Glob(filepath.Join(lost, "other", "*"))
					metadataWrite(t, paths[0], "mutated original")
				}
				if name == "mutation-empty-lost" {
					metadataWrite(t, target, "new recovery bytes")
				}
				if out, err := v.Run(context.Background(), root, metadataStatus...); err != nil || out != "" {
					t.Fatalf("source mutation affected isolated view: %q %v", out, err)
				}
				if err := v.verify(); !errors.Is(err, ErrUnsafeGitMetadata) {
					t.Fatal("source mutation undetected", err)
				}
				return
			}
			v, err := prepareMetadata(context.Background(), root, r, budget)
			if v != nil {
				v.Close()
			}
			if !errors.Is(err, ErrUnsafeGitMetadata) {
				t.Fatal("unsafe/unknown maintenance admitted", err)
			}
			t.Logf("typed refusal: %v", err)
		})
	}
}

// The finite envelope gate must also reject unreviewed sidecar versions/hashes.
func TestMaintenance_ReverseAndMtimesFormats(t *testing.T) {
	for _, sig := range []string{"RIDX", "MTME"} {
		for _, field := range []int{4, 8} {
			p := filepath.Join(t.TempDir(), "input")
			data := make([]byte, 52)
			copy(data, sig)
			binary.BigEndian.PutUint32(data[4:8], 1)
			binary.BigEndian.PutUint32(data[8:12], 1)
			binary.BigEndian.PutUint32(data[field:field+4], 2)
			if err := os.WriteFile(p, data, 0600); err != nil {
				t.Fatal(err)
			}
			name := "pack-" + strings.Repeat("a", 40) + ".rev"
			if sig == "MTME" {
				name = "pack-" + strings.Repeat("a", 40) + ".mtimes"
			}
			if err := admitMaintenanceFile(p, name, nil); !errors.Is(err, ErrUnsafeGitMetadata) {
				t.Fatal("unknown sidecar format admitted", err)
			}
		}
	}
}
