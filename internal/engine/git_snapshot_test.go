package engine_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ammaarrehman/hammerhead/internal/app"
	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/reporter"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func healthCoverage(t *testing.T, res *engine.ScanResult) scanstate.CheckCoverage {
	t.Helper()
	for _, c := range res.Coverage.Checks {
		if c.RuleID == "GIT-002" {
			return c
		}
	}
	t.Fatal("missing GIT-002 coverage")
	return scanstate.CheckCoverage{}
}
func hasGitDiagnostic(res *engine.ScanResult, code scanstate.ReasonCode) bool {
	for _, d := range res.Diagnostics {
		if d.RuleID == "GIT-002" && d.Code == code {
			return true
		}
	}
	return false
}

func TestEngine_GitUnavailablePreservesNativeScan(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "id_rsa"), []byte("synthetic credential file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), root, nil)
	if err != nil || res.Status != scanstate.StatusCompleted || healthCoverage(t, res).Status != scanstate.CheckStatusUnavailable || !hasGitDiagnostic(res, scanstate.ReasonGitUnavailable) {
		t.Fatal(res, err)
	}
	native := false
	for _, f := range res.Findings {
		if f.RuleID == "FILE-001" {
			native = true
		}
		if f.RuleID == "GIT-002" {
			t.Fatal(f)
		}
	}
	if !native {
		t.Fatal("native check was not run")
	}
}

func TestEngine_GitUnavailableVisibleWithZeroFindings(t *testing.T) {
	reg := engine.NewRegistry()
	if err := reg.Add(&check.GitHealthCheck{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	res, err := engine.New(reg).Scan(context.Background(), t.TempDir(), nil)
	if err != nil || res.Status != scanstate.StatusCompleted || len(res.Findings) != 0 || healthCoverage(t, res).Status != scanstate.CheckStatusUnavailable {
		t.Fatal(res, err)
	}
	for _, quiet := range []bool{false, true} {
		var out bytes.Buffer
		r := &reporter.Terminal{Writer: &out, Quiet: quiet}
		if err := r.Report(res); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Git executable unavailable") {
			t.Fatalf("invisible unavailable: %q", out.String())
		}
	}
	var out bytes.Buffer
	r := &reporter.JSON{Writer: &out}
	if err := r.Report(res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"unavailable"`) || !strings.Contains(out.String(), `"git_unavailable"`) {
		t.Fatal(out.String())
	}
	if app.ExitCode(res, app.ThresholdPolicy{Disabled: true}) != 0 {
		t.Fatal("missing Git made native scan fail")
	}
}

func TestEngine_GitCorruptionIsPartialWithNone(t *testing.T) {
	for _, kind := range []string{"config", "index"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "git", "init")
			cmd.Dir = root
			if err := cmd.Run(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".git", kind), []byte("[broken secret_sentinel\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "id_rsa"), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), root, nil)
			if err != nil || res.Status != scanstate.StatusPartial || healthCoverage(t, res).Status != scanstate.CheckStatusPartial || !hasGitDiagnostic(res, scanstate.ReasonGitFailure) || app.ExitCode(res, app.ThresholdPolicy{Disabled: true}) != 2 {
				t.Fatal(res, err)
			}
			native := false
			for _, f := range res.Findings {
				if f.RuleID == "FILE-001" {
					native = true
				}
				if f.RuleID == "GIT-002" {
					t.Fatal("false health finding", f)
				}
			}
			if !native {
				t.Fatal("native observations discarded")
			}
			for _, d := range res.Diagnostics {
				if strings.Contains(d.SafeMessage, "secret_sentinel") {
					t.Fatal(d)
				}
			}
		})
	}
}

func TestEngine_ValidatesRootBeforeGit(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "invoked")
	script := "#!/bin/sh\n: > '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	file := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), root, nil)
		if err == nil || res == nil || res.Status != scanstate.StatusFailed {
			t.Fatal(res, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := engine.New(engine.DefaultRegistry()).Scan(ctx, t.TempDir(), nil)
	if !errors.Is(err, context.Canceled) || res.Status != scanstate.StatusCancelled {
		t.Fatal(res, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("Git ran before root validation or after pre-cancel", err)
	}
}

func TestEngine_GitSnapshotCollectedOnceBeforeChecks(t *testing.T) {
	root, rootErr := filepath.EvalSymlinks(t.TempDir())
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	log := installSnapshotGit(t, root, "printf '?? new\\000'", "printf 'refs/heads/main\\n'")

	res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), root, nil)
	if err != nil || res.Status != scanstate.StatusCompleted || healthCoverage(t, res).Status != scanstate.CheckStatusCompleted {
		t.Fatal(res, err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 4 || strings.Count(string(data), "status --porcelain") != 1 || strings.Count(string(data), "symbolic-ref") != 1 {
		t.Fatal(string(data))
	}
	count := 0
	for _, f := range res.Findings {
		if f.RuleID == "GIT-002" {
			count++
			if f.Evidence != "Modified files: 0, Untracked files: 1" {
				t.Fatal(f)
			}
		}
	}
	if count != 1 {
		t.Fatal("snapshot not consumed", res.Findings)
	}
}

// installSnapshotGit provides a trusted executable outside the target. It uses
// shell builtins, records calls, and supplies unborn-branch/status responses.
func installSnapshotGit(t *testing.T, root, statusBody, branchBody string) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\ncase \"$*\" in\n" +
		"*'rev-parse --show-toplevel') printf '%s\\n' '" + root + "';;\n" +
		"*'symbolic-ref --quiet HEAD') " + branchBody + ";;\n" +
		"*'show-ref --verify --quiet refs/heads/main') exit 1;;\n" +
		"*'status --porcelain=v1 -z --ignore-submodules=all') " + statusBody + ";;\n" +
		"*) exit 128;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return log
}

func TestEngine_GitFailuresCannotLookClean(t *testing.T) {
	for _, tc := range []struct{ name, status, branch string }{
		{"truncated", "printf '?? good\\000 M truncated'", "printf 'refs/heads/main\\n'"},
		{"malformed", "printf 'ZZ bad\\000'", "printf 'refs/heads/main\\n'"},
		{"status-exit", "printf 'secret_sentinel' >&2; exit 128", "printf 'refs/heads/main\\n'"},
		{"branch-exit-1-with-diagnostic", "printf '?? misleading\\000'", "printf 'secret_sentinel' >&2; exit 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			installSnapshotGit(t, root, tc.status, tc.branch)
			res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), root, nil)
			if err != nil || res.Status != scanstate.StatusPartial || healthCoverage(t, res).Status != scanstate.CheckStatusPartial || !hasGitDiagnostic(res, scanstate.ReasonGitFailure) || app.ExitCode(res, app.ThresholdPolicy{Disabled: true}) != 2 {
				t.Fatal(res, err)
			}
			for _, f := range res.Findings {
				if f.RuleID == "GIT-002" {
					t.Fatal("incomplete Git emitted health finding", f)
				}
			}
			for _, d := range res.Diagnostics {
				if strings.Contains(d.SafeMessage, "secret_sentinel") {
					t.Fatal(d)
				}
			}
		})
	}
}

func TestEngine_GitUnavailableDiagnosticsStayBounded(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	limits := scanstate.ProductionLimits()
	limits.MaxDiagnosticSamples = 0
	res, err := engine.New(engine.DefaultRegistry()).Scan(context.Background(), t.TempDir(), &engine.ScanConfig{Limits: &limits})
	if err != nil || res.Status != scanstate.StatusCompleted || len(res.Diagnostics) != 0 || healthCoverage(t, res).Status != scanstate.CheckStatusUnavailable {
		t.Fatal(res, err)
	}
	reasonFound := false
	for _, r := range res.Coverage.Reasons {
		if r.Code == scanstate.ReasonGitUnavailable && r.Count == 1 {
			reasonFound = true
		}
	}
	if !reasonFound || res.Coverage.DiagnosticExamplesOmitted == nil || *res.Coverage.DiagnosticExamplesOmitted != 1 {
		t.Fatal(res.Coverage)
	}
}

func TestEngine_GitCancellationDuringSnapshot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "status-started")
	installSnapshotGit(t, root, ": > '"+marker+"'; while :; do :; done", "printf 'refs/heads/main\\n'")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type response struct {
		result *engine.ScanResult
		err    error
	}
	done := make(chan response, 1)
	go func() {
		res, err := engine.New(engine.DefaultRegistry()).Scan(ctx, root, nil)
		done <- response{res, err}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	watchdog := time.NewTimer(3 * time.Second)
	defer watchdog.Stop()
ready:
	for {
		select {
		case <-ticker.C:
			if _, err := os.Stat(marker); err == nil {
				break ready
			}
		case result := <-done:
			t.Fatalf("scan ended before synchronized status stage: %v", result)
		case <-watchdog.C:
			t.Fatal("Git status never started")
		}
	}
	cancel()
	select {
	case r := <-done:
		if !errors.Is(r.err, context.Canceled) || r.result == nil || r.result.Status != scanstate.StatusCancelled || len(r.result.Findings) != 0 || app.ExitCode(r.result, app.ThresholdPolicy{Disabled: true}) != 2 || !hasGitDiagnostic(r.result, scanstate.ReasonUserCancelled) {
			t.Fatal(r)
		}
		if healthCoverage(t, r.result).Status != scanstate.CheckStatusNotRun {
			t.Fatal(r.result.Coverage.Checks)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Git snapshot cancellation exceeded cooperative watchdog")
	}
}
