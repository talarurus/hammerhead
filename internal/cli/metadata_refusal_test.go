package cli_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/scanstate"
)

func TestA2R3B1_MetadataRefusalReports(t *testing.T) {
	for _, retained := range []bool{false, true} {
		for _, format := range []string{"json", "terminal", "quiet"} {
			for _, threshold := range []string{"none", "high"} {
				t.Run(format+"/"+threshold+"/retained="+strconv.FormatBool(retained), func(t *testing.T) {
					root := g11EmptyRepo(t)
					for _, n := range []string{"refs", "objects"} {
						if err := os.MkdirAll(filepath.Join(root, ".git", n), 0700); err != nil {
							t.Fatal(err)
						}
					}
					for n, data := range map[string]string{"HEAD": "ref: refs/heads/main\n", "config": "[core]\nrepositoryformatversion=0\n[include]\npath=../UNTRUSTED_VALUE.cfg\n"} {
						if err := os.WriteFile(filepath.Join(root, ".git", n), []byte(data), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if retained {
						if err := os.WriteFile(filepath.Join(root, "a.key"), []byte("synthetic filename observation"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					home := t.TempDir()
					t.Setenv("HOME", home)
					t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
					args := []string{"audit", root, "--fail-on", threshold}
					if format == "quiet" {
						args = append(args, "--quiet")
					} else {
						args = append(args, "--output", format)
					}
					out, diag, code := integratedRun(t, 10*time.Second, os.Getenv("PATH"), args...)
					if code != 2 || strings.Contains(string(out)+string(diag), "UNTRUSTED_VALUE") {
						t.Fatalf("code=%d stdout=%s stderr=%s", code, out, diag)
					}
					if format == "json" {
						r := integratedJSON(t, out)
						if r.Status != scanstate.StatusPartial {
							t.Fatal(r.Status)
						}
						found := false
						for _, f := range r.Findings {
							if f.RuleID == "GIT-002" {
								t.Fatal("fabricated Git finding", f)
							}
							found = found || f.RuleID == "FILE-001" && f.Path == "a.key"
						}
						if found != retained || (!retained && len(r.Findings) != 0) {
							t.Fatal("native result lost", r.Findings)
						}
						partial := false
						for _, c := range r.Coverage.Checks {
							partial = partial || c.RuleID == "GIT-002" && c.Status == scanstate.CheckStatusPartial
						}
						refused := false
						for _, d := range r.Diagnostics {
							refused = refused || d.RuleID == "GIT-002" && d.Code == scanstate.ReasonGitFailure && strings.Contains(d.SafeMessage, "refused")
						}
						if !partial || !refused {
							t.Fatal(r.Coverage, r.Diagnostics)
						}
					} else {
						stream := string(out)
						if format == "quiet" {
							stream = string(diag)
							if !retained && len(out) != 0 {
								t.Fatalf("quiet stdout=%q", out)
							}
						}
						if !strings.Contains(stream, "PARTIAL") || !strings.Contains(stream, "refused") {
							t.Fatalf("refusal invisible: %s", stream)
						}
						if retained && !strings.Contains(string(out), "[FILE-001]") {
							t.Fatal("native finding invisible")
						}
					}
				})
			}
		}
	}
}
