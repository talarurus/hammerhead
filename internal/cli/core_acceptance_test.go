package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/product"
	"github.com/talarurus/hammerhead/internal/scanstate"
)

func coreWrite(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertCoreContract(t *testing.T, out []byte) {
	t.Helper()
	var r struct {
		Product string        `json:"product"`
		Version string        `json:"version"`
		Schema  string        `json:"schema"`
		Scope   product.Scope `json:"scope"`
		Summary struct {
			Checks int `json:"checks_attempted"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if r.Product != product.Name || r.Version != product.Version || r.Schema != product.Schema || !reflect.DeepEqual(r.Scope, product.CoreScope()) || r.Summary.Checks != 6 {
		t.Fatalf("incorrect Core identity/scope: %+v", r)
	}
	scanned := integratedJSON(t, out)
	if scanned.Status != scanstate.StatusCompleted || len(scanned.Coverage.Checks) != 6 {
		t.Fatalf("Core did not complete all promised checks: %+v", scanned)
	}
	seen := map[string]bool{}
	for _, c := range scanned.Coverage.Checks {
		if c.Status != scanstate.CheckStatusCompleted || c.RuleID == "GIT-002" {
			t.Fatalf("false completion: %+v", c)
		}
		seen[c.RuleID] = true
	}
	for _, id := range product.CoreScope().IncludedRules {
		if !seen[id] {
			t.Fatalf("missing rule %s", id)
		}
	}
	for _, f := range scanned.Findings {
		if !seen[f.RuleID] {
			t.Fatalf("unpromised rule executed: %+v", f)
		}
	}
	for key := range scanned.Coverage.Policy.EffectiveLimits {
		if strings.Contains(key, "git_") {
			t.Fatalf("Git policy leaked into Core: %s", key)
		}
	}
}

// Every included rule has an executable-level positive and a clean control.
func TestCore_RuleAcceptance(t *testing.T) {
	for _, id := range append([]string{"clean"}, product.CoreScope().IncludedRules...) {
		t.Run(id, func(t *testing.T) {
			root := g11EmptyRepo(t)
			wantExit := 0
			switch id {
			case "FILE-001":
				coreWrite(t, root, "id_rsa", "synthetic filename only\n")
				wantExit = 1
			case "FILE-002":
				coreWrite(t, root, "large.txt", strings.Repeat("a", 2048))
			case "GIT-001":
				if err := os.Remove(filepath.Join(root, ".gitignore")); err != nil {
					t.Fatal(err)
				}
			case "PROJ-001":
				if err := os.Remove(filepath.Join(root, "README.md")); err != nil {
					t.Fatal(err)
				}
			case "PROJ-002":
				coreWrite(t, root, "go.mod", "module synthetic.invalid/core-fixture\n")
			case "SEC-001":
				coreWrite(t, root, "notes.txt", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC HEADER ONLY\n")
				wantExit = 1
			}
			out, diag, code := integratedRun(t, 5*time.Second, t.TempDir(), "audit", root, "--output", "json", "--max-file-size", "1KB")
			if code != wantExit || len(diag) != 0 {
				t.Fatalf("exit=%d want=%d stderr=%s", code, wantExit, diag)
			}
			assertCoreContract(t, out)
			r := integratedJSON(t, out)
			wantCount := 1
			if id == "clean" {
				wantCount = 0
			}
			if len(r.Findings) != wantCount {
				t.Fatalf("findings=%+v", r.Findings)
			}
			if wantCount == 1 && r.Findings[0].RuleID != id {
				t.Fatalf("wrong detector: %+v", r.Findings)
			}
		})
	}
}

func TestCore_GitAndHelperIsolation(t *testing.T) {
	// A live sentinel is a positive control: direct invocation must leave evidence.
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "started")
	sentinel := "#!/bin/sh\nprintf 'started\\n' >> \"$CORE_SENTINEL\"\nexit 91\n"
	for _, name := range []string{"git", "git-credential-core-sentinel", "core-helper", "sh"} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte(sentinel), 0700); err != nil {
			t.Fatal(err)
		}
	}
	control := exec.Command(filepath.Join(bin, "git"), "--version")
	control.Env = append(os.Environ(), "CORE_SENTINEL="+marker)
	if err := control.Run(); err == nil {
		t.Fatal("sentinel negative control failed")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "started\n" {
		t.Fatalf("sentinel is inert: %s %v", data, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CORE_SENTINEL", marker)
	t.Setenv("GIT_EXEC_PATH", bin)
	t.Setenv("GIT_SSH", filepath.Join(bin, "core-helper"))
	t.Setenv("GIT_SSH_COMMAND", filepath.Join(bin, "core-helper"))
	t.Setenv("GIT_ASKPASS", filepath.Join(bin, "core-helper"))
	t.Setenv("SSH_ASKPASS", filepath.Join(bin, "core-helper"))
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "credential.helper")
	t.Setenv("GIT_CONFIG_VALUE_0", "!"+filepath.Join(bin, "core-helper"))
	t.Setenv("GIT_CONFIG_KEY_1", "core.fsmonitor")
	t.Setenv("GIT_CONFIG_VALUE_1", filepath.Join(bin, "core-helper"))
	for _, metadata := range []string{"none", "directory", "gitfile", "symlink", "nested"} {
		t.Run(metadata, func(t *testing.T) {
			root := g11EmptyRepo(t)
			malicious := t.TempDir()
			coreWrite(t, malicious, "HEAD", "ref: refs/heads/main\n")
			coreWrite(t, malicious, "config", "[core]\nrepositoryformatversion=0\nfsmonitor="+filepath.Join(bin, "core-helper")+"\n[credential]\nhelper=!"+filepath.Join(bin, "core-helper")+"\n[include]\npath=UNTRUSTED_CONFIG_SENTINEL\n[filter \"sentinel\"]\nprocess="+filepath.Join(bin, "core-helper")+"\n")
			switch metadata {
			case "directory":
				if err := os.CopyFS(filepath.Join(root, ".git"), os.DirFS(malicious)); err != nil {
					t.Fatal(err)
				}
				coreWrite(t, root, ".git/hooks/post-checkout", sentinel)
			case "gitfile":
				coreWrite(t, root, ".git", "gitdir: "+malicious+"\n")
			case "symlink":
				if err := os.Symlink(malicious, filepath.Join(root, ".git")); err != nil {
					t.Fatal(err)
				}
			case "nested":
				coreWrite(t, root, "nested/.git/config", "UNTRUSTED_CONFIG_SENTINEL")
			}
			t.Setenv("GIT_DIR", malicious)
			for _, format := range []string{"json", "terminal", "quiet"} {
				args := []string{"audit", root}
				if format == "quiet" {
					args = append(args, "--quiet")
				} else {
					args = append(args, "--output", format)
				}
				out, diag, code := integratedRun(t, 5*time.Second, bin, args...)
				if code != 0 || bytes.Contains(append(out, diag...), []byte("UNTRUSTED_CONFIG_SENTINEL")) {
					t.Fatalf("Core consumed Git metadata: %d %s %s", code, out, diag)
				}
				if format == "json" {
					assertCoreContract(t, out)
				} else {
					stream := out
					if format == "quiet" {
						stream = diag
						if len(out) != 0 {
							t.Fatalf("clean quiet stdout: %s", out)
						}
					}
					if !bytes.Contains(stream, []byte("GIT-002: NOT EVALUATED")) || !bytes.Contains(stream, []byte("COMPLETED")) {
						t.Fatalf("scope invisible: %s", stream)
					}
				}
			}
		})
	}
	for _, args := range [][]string{{"--help"}, {"audit", "--help"}, {"version"}, {"audit", "--enable-git"}, {"audit", "--full-git"}, {"audit", "--git"}} {
		out, diag, code := integratedRun(t, 5*time.Second, bin, args...)
		if strings.Contains(strings.Join(args, " "), "help") || args[0] == "version" {
			if code != 0 || !bytes.Contains(out, []byte("Hammerhead Core")) || !bytes.Contains(out, []byte("NOT EVALUATED")) {
				t.Fatalf("ambiguous identity: %s %s", out, diag)
			}
		} else if code != 2 {
			t.Fatalf("unqualified mode accepted: %v code %d", args, code)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Core started Git or a helper: %v", err)
	}
}

func TestCore_RedactionAcrossReporters(t *testing.T) {
	key := "AKIA0123456789ABCDEF"
	secret := "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b"
	root := g11EmptyRepo(t)
	coreWrite(t, root, "settings.txt", "aws_access_key_id="+key+"\naws_secret_access_key="+secret+"\n")
	for _, format := range []string{"json", "terminal", "quiet"} {
		args := []string{"audit", root}
		if format == "quiet" {
			args = append(args, "--quiet")
		} else {
			args = append(args, "--output", format)
		}
		out, diag, code := integratedRun(t, 5*time.Second, t.TempDir(), args...)
		stream := append(out, diag...)
		if code != 1 || !bytes.Contains(stream, []byte("SEC-001")) || bytes.Contains(stream, []byte(key)) || bytes.Contains(stream, []byte(secret)) {
			t.Fatalf("redaction/detection failed: code=%d %s", code, stream)
		}
	}
}
