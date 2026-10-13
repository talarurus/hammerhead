//go:build darwin || linux

package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/talarurus/hammerhead/internal/scanstate"
)

// B2 helpers operate only on fixed names below their own executable's owned
// fixture directory. No network, credential, transport or arbitrary shell code
// is implemented. init dispatch also works in race-instrumented test binaries.
func init() {
	if len(os.Args) > 2 && os.Args[1] == "--hh-b2-sentinel" {
		os.Exit(b2SentinelMain(os.Args[2]))
	}
	if filepath.Base(os.Args[0]) == "git" {
		exe, err := os.Executable()
		if err == nil && strings.Contains(exe, "hh-b2-") && filepath.Base(filepath.Dir(exe)) == "controls" {
			os.Exit(b2ProxyMain(exe))
		}
	}
}

func b2Append(path string, data []byte) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return errors.New("B2 bounded owned log unavailable")
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, writeErr := f.Write(data)
	return errors.Join(writeErr, f.Close())
}

func b2SentinelMain(mode string) int {
	exe, err := os.Executable()
	if err != nil || filepath.Base(filepath.Dir(exe)) != "controls" {
		return 90
	}
	switch mode {
	case "clean", "process", "process-exit", "fsmonitor", "hook":
	default:
		return 91
	}
	if err := b2Append(filepath.Join(filepath.Dir(exe), "START.log"), []byte("START\n")); err != nil {
		return 92
	}
	switch mode {
	case "clean":
		_, err = io.Copy(os.Stdout, io.LimitReader(os.Stdin, 1<<20))
	case "process-exit":
		// START is written before reading even the client's first packet.
		return 1
	case "process":
		err = b2FilterProtocol(os.Stdin, os.Stdout)
	case "fsmonitor":
		_, err = os.Stdout.Write([]byte("b2-token\x00"))
	}
	if err != nil {
		return 93
	}
	return 0
}

// Minimal clean-only v2 packet protocol for synthetic calibration input.
func b2Packets(r io.Reader) ([]byte, error) {
	var out []byte
	for {
		var header [4]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(string(header[:]), 16, 16)
		if err != nil || (n != 0 && n < 4) || n > 65520 || len(out)+int(n) > 1<<20 {
			return nil, errors.New("B2 packet bound")
		}
		if n == 0 {
			return out, nil
		}
		data := make([]byte, int(n)-4)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		out = append(out, data...)
	}
}

func b2Packet(data string) string { return fmt.Sprintf("%04x%s", len(data)+4, data) }

func b2FilterProtocol(r io.Reader, w io.Writer) error {
	hello, err := b2Packets(r)
	if err != nil || string(hello) != "git-filter-client\nversion=2\n" {
		return errors.New("B2 client handshake")
	}
	if _, err := io.WriteString(w, b2Packet("git-filter-server\n")+b2Packet("version=2\n")+"0000"); err != nil {
		return err
	}
	if _, err := b2Packets(r); err != nil {
		return err
	}
	if _, err := io.WriteString(w, b2Packet("capability=clean\n")+"0000"); err != nil {
		return err
	}
	request, err := b2Packets(r)
	if err != nil || !bytes.Contains(request, []byte("command=clean\n")) {
		return errors.New("B2 clean request")
	}
	data, err := b2Packets(r)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, b2Packet("status=success\n")+"0000"+b2Packet(string(data))+"0000"+"0000")
	return err
}

type b2ProxyPolicy struct {
	Protocol, Mode, RealGit, Repo, Helper, ConfigSHA256 string
}

func b2ProxyMain(exe string) int {
	controls := filepath.Dir(exe)
	data, err := os.ReadFile(filepath.Join(controls, "policy.json"))
	var p b2ProxyPolicy
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &p) != nil || p.Protocol != "owned-B2-proxy-v1" || p.Repo != filepath.Join(filepath.Dir(controls), "repo") || p.Helper != filepath.Join(controls, "sentinel") {
		return 94
	}
	args := os.Args[1:]
	query := args
	for len(query) > 0 {
		if query[0] == "--no-pager" || query[0] == "--no-lazy-fetch" {
			query = query[1:]
		} else if len(query) >= 2 && query[0] == "-c" {
			query = query[2:]
		} else {
			break
		}
	}
	allowed := queryAllowed(query) || (len(query) == 6 && query[0] == "config" && query[1] == "--null" && query[2] == "--list" && query[3] == "--no-includes" && query[4] == "--file") || strings.Join(query, "\x00") == "var\x00GIT_ATTR_SYSTEM" || strings.Join(query, "\x00") == "ls-files\x00--stage\x00--sparse\x00-v\x00-z"
	guard := "ok"
	if !allowed {
		guard = "unreviewed command blocked"
	}
	if p.Mode == "baseline" {
		config, e := os.ReadFile(filepath.Join(p.Repo, ".git", "config"))
		digest := sha256.Sum256(config)
		if e != nil || hex.EncodeToString(digest[:]) != p.ConfigSHA256 || len(query) == 0 || !queryAllowed(query) {
			guard = "baseline fixture changed or unreviewed query"
		}
	} else {
		gd, home, xdg := os.Getenv("GIT_DIR"), os.Getenv("HOME"), os.Getenv("XDG_CONFIG_HOME")
		live, e := os.ReadFile(filepath.Join(gd, "config"))
		if !filepath.IsAbs(gd) || gd == filepath.Join(p.Repo, ".git") || filepath.Dir(gd) != filepath.Dir(home) || xdg != filepath.Join(home, "xdg") || e != nil || bytes.Contains(live, []byte("filter")) || bytes.Contains(live, []byte("include")) || !strings.Contains(strings.Join(args, "\x00"), "--no-lazy-fetch\x00") || os.Getenv("GIT_NO_LAZY_FETCH") != "1" || os.Getenv("GIT_CONFIG_GLOBAL") != "/dev/null" || os.Getenv("GIT_CONFIG_SYSTEM") != "/dev/null" {
			guard = "unsafe candidate startup blocked"
		}
		for _, env := range os.Environ() {
			name, _, _ := strings.Cut(env, "=")
			switch name {
			case "PATH", "HOME", "XDG_CONFIG_HOME", "GIT_DIR", "GIT_WORK_TREE", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_OPTIONAL_LOCKS", "GIT_NO_LAZY_FETCH", "GIT_ATTR_NOSYSTEM", "LC_ALL":
			default:
				guard = "uncontrolled candidate environment blocked"
			}
		}
		if p.Mode == "promisor" && (len(query) == 0 || query[0] != "config") {
			// Never permit a real fetch experiment, even if admission regresses.
			guard = "promisor query before refusal blocked"
		}
	}
	event, _ := json.Marshal(map[string]any{"argv": args, "query": query, "guard": guard, "mode": p.Mode, "GIT_DIR": os.Getenv("GIT_DIR"), "HOME": os.Getenv("HOME"), "GIT_NO_LAZY_FETCH": os.Getenv("GIT_NO_LAZY_FETCH"), "at": time.Now().UTC()})
	if b2Append(filepath.Join(controls, "proxy.jsonl"), append(event, '\n')) != nil || guard != "ok" {
		return 95
	}
	if len(query) > 0 && ((p.Mode == "mutate-prepare" && query[0] == "config") || (p.Mode == "mutate-after" && query[0] == "rev-parse" && len(query) == 2 && query[1] == "--show-toplevel")) {
		// Deterministic controlled mutation: copied config is already inert input.
		f, e := os.OpenFile(filepath.Join(p.Repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
		if e != nil {
			return 96
		}
		_, e = io.WriteString(f, b2FilterConfig(p.Helper, "clean", false))
		if errors.Join(e, f.Close()) != nil {
			return 96
		}
	}
	if err := syscall.Exec(p.RealGit, append([]string{p.RealGit}, args...), os.Environ()); err != nil {
		return 97
	}
	return 0
}

type b2Command struct {
	Argv                   []string
	Exit                   int
	Seconds                float64
	Timeout, ParentTimeout bool
	Stdout, Stderr         string
}

type b2Fixture struct {
	t                                     *testing.T
	area, repo, controls, helper, realGit string
	home                                  string
	ctx                                   context.Context
	cancel                                context.CancelFunc
	watchdog                              *time.Timer
	commands                              []b2Command
	armed, preserve                       bool
	policy                                b2ProxyPolicy
}

func b2CandidateBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("HAMMERHEAD_B2_CANDIDATE"); path != "" {
		return path
	}
	// The calling top-level test owns the binary through all its subtests.
	// testing cleans this allocation on success and on Fatal/build failure.
	binary := filepath.Join(t.TempDir(), "hammerhead")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, "../../cmd/hammerhead")
	// Compiler/platform scratch data belongs to the same test allocation.
	cmd.Env = append(os.Environ(), "TMPDIR="+filepath.Dir(binary))
	out, err := cmd.CombinedOutput()
	if err := errors.Join(err, ctx.Err()); err != nil {
		t.Fatalf("B2 candidate build: %v (%s)", err, out)
	}
	return binary
}

func b2New(t *testing.T, name string, trackedAttributes, nested bool) *b2Fixture {
	t.Helper()
	area, err := os.MkdirTemp("", "hh-b2-"+name+"-")
	if err != nil {
		t.Fatal(err)
	}
	area, err = filepath.EvalSymlinks(area)
	if err != nil {
		t.Fatal(err)
	}
	f := &b2Fixture{t: t, area: area, repo: filepath.Join(area, "repo"), controls: filepath.Join(area, "controls"), home: filepath.Join(area, "home")}
	f.ctx, f.cancel = context.WithTimeout(context.Background(), 20*time.Second)
	evidence := os.Getenv("HAMMERHEAD_B2_EVIDENCE")
	f.watchdog = time.AfterFunc(20*time.Second, func() {
		message := "B2 parent watchdog expired; owned fixture preserved: " + area + "\n"
		if evidence != "" {
			_ = os.WriteFile(filepath.Join(evidence, filepath.Base(area)+"-WATCHDOG.txt"), []byte(message), 0600)
		}
		_, _ = os.Stderr.WriteString(message)
		os.Exit(124)
	})
	t.Cleanup(f.finish)
	for _, dir := range []string{f.repo, f.controls, f.home, filepath.Join(area, "empty-template")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewGitRunner(f.repo)
	if err != nil {
		t.Fatal(err)
	}
	f.realGit = r.gitPath
	for _, name := range []string{"START.log", "proxy.jsonl"} {
		metadataWrite(t, filepath.Join(f.controls, name), "")
	}
	f.setup("init", "--template="+filepath.Join(area, "empty-template"), "-b", "main")
	f.setup("config", "core.trustctime", "false")
	f.setup("config", "core.checkstat", "minimal")
	payload := "payload.txt"
	if nested {
		payload = "nested/payload.txt"
	}
	metadataWrite(t, filepath.Join(f.repo, payload), "AAAAAAAA\n")
	if trackedAttributes {
		metadataWrite(t, filepath.Join(f.repo, ".gitattributes"), payload+" filter=b2\n")
	}
	f.setup("add", ".")
	f.setup("-c", "user.name=B2 Fixture", "-c", "user.email=b2@example.invalid", "commit", "-m", "synthetic fixture")
	stamp := time.Unix(1500000000, 123456789)
	if err := os.Chtimes(filepath.Join(f.repo, payload), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	f.setup("add", payload)
	if err := os.Chtimes(filepath.Join(f.repo, ".git", "index"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	metadataWrite(t, filepath.Join(f.repo, payload), "BBBBBBBB\n")
	if err := os.Chtimes(filepath.Join(f.repo, payload), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if !trackedAttributes {
		attr := filepath.Join(f.repo, ".gitattributes")
		selection := payload
		if nested {
			attr, selection = filepath.Join(f.repo, "nested", ".gitattributes"), "payload.txt"
		}
		metadataWrite(t, attr, selection+" filter=b2\n")
	}
	metadataWrite(t, filepath.Join(f.repo, "retained.key"), "synthetic filename-only finding\n")
	// Commits, stat cache and content are ready before any helper definition.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.helper = filepath.Join(f.controls, "sentinel")
	if err := os.Link(exe, f.helper); err != nil {
		// Cross-device test binaries require a checked bounded owned copy.
		data, e := os.ReadFile(exe)
		if e != nil || len(data) > 128<<20 {
			t.Fatal("B2 test executable copy bound", e)
		}
		if e := os.WriteFile(f.helper, data, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if err := os.Link(f.helper, filepath.Join(f.controls, "git")); err != nil {
		t.Fatal(err)
	}
	f.policy = b2ProxyPolicy{Protocol: "owned-B2-proxy-v1", Mode: "candidate", RealGit: f.realGit, Repo: f.repo, Helper: f.helper}
	f.setPolicy()
	t.Setenv("HOME", f.home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(f.home, "xdg"))
	t.Setenv("PATH", f.controls+string(os.PathListSeparator)+filepath.Dir(f.realGit)+string(os.PathListSeparator)+"/usr/bin:/bin")
	return f
}

func (f *b2Fixture) env(proxy bool) []string {
	path := filepath.Dir(f.realGit) + ":/usr/bin:/bin"
	if proxy {
		path = f.controls + ":" + path
	}
	return []string{"PATH=" + path, "HOME=" + f.home, "XDG_CONFIG_HOME=" + filepath.Join(f.home, "xdg"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_ATTR_NOSYSTEM=1", "LC_ALL=C"}
}

func (f *b2Fixture) run(exe string, args []string, input string, proxy bool) b2Command {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	cmd := exec.Command(exe, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = f.repo, f.env(proxy), strings.NewReader(input)
	setupSysProcAttr(cmd)
	var out, diag bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitWriter{buf: &out, limit: 1 << 20, cancel: cancel}, &limitWriter{buf: &diag, limit: 64 << 10, cancel: cancel}
	cmd.WaitDelay = time.Second
	start := time.Now()
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	waited := false
	select {
	case waitErr = <-done:
		waited = true
	case <-ctx.Done():
	}
	waitErr, cleanupErr := cleanupProcessGroup(cmd, done, waitErr, waited)
	exit := 0
	if waitErr != nil {
		exit = -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exit = ee.ExitCode()
		}
	}
	record := b2Command{Argv: append([]string{exe}, args...), Exit: exit, Seconds: time.Since(start).Seconds(), Timeout: ctx.Err() != nil, ParentTimeout: f.ctx.Err() != nil, Stdout: out.String(), Stderr: diag.String()}
	f.commands = append(f.commands, record)
	if cleanupErr != nil || record.Timeout {
		f.preserve = true
		f.t.Fatalf("B2 bounded child/cleanup failure: %+v %v", record, cleanupErr)
	}
	return record
}

func (f *b2Fixture) setup(args ...string) string {
	f.t.Helper()
	if f.armed {
		f.t.Fatal("original in-place Git prohibited after fixture helper installation")
	}
	prefix := []string{"--no-pager", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null"}
	r := f.run(f.realGit, append(prefix, args...), "", false)
	if r.Exit != 0 {
		f.t.Fatalf("B2 fixture setup failed: %+v", r)
	}
	return r.Stdout
}

func b2FilterConfig(helper, mode string, required bool) string {
	key := "clean"
	if strings.HasPrefix(mode, "process") {
		key = "process"
	}
	command := "'" + strings.ReplaceAll(helper, "'", "'\\''") + "' --hh-b2-sentinel " + mode
	return "\n[filter \"b2\"]\n" + key + " = " + strconv.Quote(command) + "\nrequired = " + strconv.FormatBool(required) + "\n"
}

func (f *b2Fixture) appendConfig(text string) {
	file, err := os.OpenFile(filepath.Join(f.repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = io.WriteString(file, text)
	if err = errors.Join(err, file.Close()); err != nil {
		f.t.Fatal(err)
	}
	f.armed = true
}

func (f *b2Fixture) setPolicy() {
	data, err := json.Marshal(f.policy)
	if err != nil {
		f.t.Fatal(err)
	}
	metadataWrite(f.t, filepath.Join(f.controls, "policy.json"), string(data))
}

func (f *b2Fixture) noStart() {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.controls, "START.log"))
	if err != nil || len(data) != 0 {
		f.preserve = true
		blocker := fmt.Sprintf("B2_SECURITY_BLOCKER: corrected candidate started sentinel; fixture preserved: %s marker=%q error=%v", f.area, data, err)
		if evidence := os.Getenv("HAMMERHEAD_B2_EVIDENCE"); evidence != "" {
			_ = os.WriteFile(filepath.Join(evidence, "SECURITY-BLOCKER.txt"), []byte(blocker), 0600)
		}
		panic(blocker)
	}
	proxy, err := os.ReadFile(filepath.Join(f.controls, "proxy.jsonl"))
	if err != nil {
		f.t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(proxy), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Guard string }
		if json.Unmarshal(line, &event) != nil || event.Guard != "ok" {
			f.preserve = true
			f.t.Fatalf("B2 safety guard activated (incomplete candidate evidence): %s", line)
		}
	}
}

func (f *b2Fixture) report(binary string, partial bool) {
	f.t.Helper()
	r := f.run(binary, []string{"audit", f.repo, "--output", "json", "--fail-on", "none"}, "", true)
	f.noStart()
	var report struct {
		Status   scanstate.Status                `json:"status"`
		Findings []struct{ RuleID, Path string } `json:"findings"`
		Coverage struct {
			Checks []struct {
				RuleID string                `json:"rule_id"`
				Status scanstate.CheckStatus `json:"status"`
			}
		} `json:"coverage"`
	}
	// Findings use explicit schema field names rather than Go-name matching.
	var raw struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
		} `json:"findings"`
	}
	if json.Unmarshal([]byte(r.Stdout), &report) != nil || json.Unmarshal([]byte(r.Stdout), &raw) != nil {
		f.t.Fatalf("B2 invalid JSON/exit: %+v", r)
	}
	retained, coverage := false, false
	for _, finding := range raw.Findings {
		retained = retained || finding.RuleID == "FILE-001" && finding.Path == "retained.key"
		if partial && finding.RuleID == "GIT-002" {
			f.t.Fatal("B2 fabricated Git finding")
		}
	}
	wantStatus, wantExit := scanstate.CheckStatusCompleted, 0
	if partial {
		wantStatus, wantExit = scanstate.CheckStatusPartial, 2
	}
	for _, check := range report.Coverage.Checks {
		coverage = coverage || check.RuleID == "GIT-002" && check.Status == wantStatus
	}
	if !retained || !coverage || r.Exit != wantExit || (partial && report.Status != scanstate.StatusPartial) {
		f.t.Fatalf("B2 refusal/retention mismatch: retained=%v coverage=%v command=%+v", retained, coverage, r)
	}
	if partial && strings.Contains(r.Stdout+r.Stderr, f.helper) {
		f.t.Fatal("B2 helper value disclosed in output")
	}
	f.t.Logf("exit=%d partial=%v native finding retained; START bytes=0", r.Exit, partial)
}

func (f *b2Fixture) finish() {
	f.watchdog.Stop()
	f.cancel()
	start, _ := os.ReadFile(filepath.Join(f.controls, "START.log"))
	proxy, _ := os.ReadFile(filepath.Join(f.controls, "proxy.jsonl"))
	config, _ := os.ReadFile(filepath.Join(f.repo, ".git", "config"))
	index, _ := os.ReadFile(filepath.Join(f.repo, ".git", "index"))
	configHash, indexHash := sha256.Sum256(config), sha256.Sum256(index)
	record := map[string]any{"test": f.t.Name(), "fixture": f.area, "failed": f.t.Failed(), "preserved": f.preserve || f.t.Failed(), "START": string(start), "proxy": string(proxy), "commands": f.commands, "config_sha256": hex.EncodeToString(configHash[:]), "index_sha256": hex.EncodeToString(indexHash[:])}
	if evidence := os.Getenv("HAMMERHEAD_B2_EVIDENCE"); evidence != "" {
		data, err := json.MarshalIndent(record, "", "  ")
		if err != nil || os.WriteFile(filepath.Join(evidence, filepath.Base(f.area)+".json"), data, 0600) != nil {
			f.t.Error("B2 evidence export failed")
		}
	}
	if f.preserve || f.t.Failed() {
		f.t.Logf("B2 fixture preserved: %s", f.area)
		return
	}
	done := make(chan error, 1)
	go func() { done <- os.RemoveAll(f.area) }()
	select {
	case err := <-done:
		if err != nil {
			f.t.Error("B2 owned fixture cleanup", err)
		}
	case <-time.After(2 * time.Second):
		f.t.Error("B2 owned fixture cleanup deadline")
	}
}

func TestB2_BaselinePositiveControl(t *testing.T) {
	baseline := os.Getenv("HAMMERHEAD_B2_BASELINE")
	if baseline == "" {
		t.Skip("B2 exact-baseline binary must be supplied by isolated reconstruction harness")
	}
	f := b2New(t, "baseline-clean", true, false)
	f.appendConfig(b2FilterConfig(f.helper, "clean", false))
	config, err := os.ReadFile(filepath.Join(f.repo, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(config)
	f.policy.Mode, f.policy.ConfigSHA256 = "baseline", hex.EncodeToString(hash[:])
	f.setPolicy()
	r := f.run(baseline, []string{"audit", f.repo, "--output", "json", "--fail-on", "none"}, "", true)
	start, err := os.ReadFile(filepath.Join(f.controls, "START.log"))
	if err != nil || len(start) == 0 || len(start)%6 != 0 || !bytes.Equal(start, bytes.Repeat([]byte("START\n"), len(start)/6)) || r.Exit != 0 {
		f.preserve = true
		t.Fatalf("B2 baseline positive control INCONCLUSIVE: marker=%q error=%v result=%+v", start, err, r)
	}
	proxy, _ := os.ReadFile(filepath.Join(f.controls, "proxy.jsonl"))
	if !bytes.Contains(proxy, []byte(`"status","--porcelain=v1","-z","--ignore-submodules=all"`)) {
		t.Fatal("B2 exact original status invocation not recorded")
	}
	t.Logf("CONFIRMED baseline exact status starts clean sentinel: %q exit=%d", start, r.Exit)
}

func TestB2_ProcessSentinelCalibration(t *testing.T) {
	for _, mode := range []string{"process", "process-exit"} {
		t.Run(mode, func(t *testing.T) {
			f := b2New(t, "calibrate-"+mode, true, false)
			input := ""
			if mode == "process" {
				input = b2Packet("git-filter-client\n") + b2Packet("version=2\n") + "0000" + b2Packet("capability=clean\n") + "0000" + b2Packet("command=clean\n") + b2Packet("pathname=payload.txt\n") + "0000" + b2Packet("SYNTHETIC\n") + "0000"
			}
			r := f.run(f.helper, []string{"--hh-b2-sentinel", mode}, input, false)
			start, _ := os.ReadFile(filepath.Join(f.controls, "START.log"))
			wantExit := 0
			if mode == "process-exit" {
				wantExit = 1
			}
			if string(start) != "START\n" || r.Exit != wantExit || (mode == "process" && !strings.Contains(r.Stdout, "SYNTHETIC\n")) {
				t.Fatal("B2 standalone sentinel calibration failed", string(start), r)
			}
			t.Logf("standalone calibration: START before handshake, exit=%d", r.Exit)
		})
	}
}

func TestB2_ConfiguredHelperRefusal(t *testing.T) {
	binary := b2CandidateBinary(t)
	for _, name := range []string{"clean-optional", "clean-required", "process", "process-exit", "include", "includeIf", "worktree-config", "untracked-attributes", "nested-untracked-attributes", "fsmonitor", "fsmonitor-false", "hooks-config", "hook-file-only", "undefined-filter", "promisor-config", "promisor-marker", "split-index", "sparse-config", "gitfile", "metadata-symlink", "linked-worktree"} {
		t.Run(name, func(t *testing.T) {
			f := b2New(t, name, !strings.Contains(name, "untracked-attributes"), strings.HasPrefix(name, "nested-"))
			partial := true
			switch name {
			case "clean-optional", "clean-required", "untracked-attributes", "nested-untracked-attributes":
				f.appendConfig(b2FilterConfig(f.helper, "clean", name == "clean-required"))
			case "process", "process-exit":
				f.appendConfig(b2FilterConfig(f.helper, name, true))
			case "include", "includeIf":
				path := filepath.Join(f.controls, "included.config")
				metadataWrite(t, path, b2FilterConfig(f.helper, "clean", true))
				section := "include"
				if name == "includeIf" {
					section = "includeIf \"onbranch:main\""
				}
				f.appendConfig("\n[" + section + "]\npath = " + strconv.Quote(path) + "\n")
			case "worktree-config":
				metadataWrite(t, filepath.Join(f.repo, ".git", "config.worktree"), b2FilterConfig(f.helper, "clean", true))
				f.appendConfig("\n[extensions]\nworktreeConfig=true\n")
			case "fsmonitor":
				f.appendConfig("\n[core]\nfsmonitor=" + strconv.Quote("'"+f.helper+"' --hh-b2-sentinel fsmonitor") + "\n")
			case "fsmonitor-false":
				f.appendConfig("\n[core]\nfsmonitor=false\n")
			case "hooks-config", "hook-file-only":
				metadataWrite(t, filepath.Join(f.repo, ".git", "hooks", "post-index-change"), "#!/bin/sh\nexec '"+f.helper+"' --hh-b2-sentinel hook\n")
				if err := os.Chmod(filepath.Join(f.repo, ".git", "hooks", "post-index-change"), 0700); err != nil {
					t.Fatal(err)
				}
				f.armed = true
				if name == "hooks-config" {
					f.appendConfig("\n[core]\nhooksPath=" + strconv.Quote(filepath.Join(f.repo, ".git", "hooks")) + "\n")
				} else {
					partial = false
				}
			case "undefined-filter":
				partial = false
			case "promisor-config":
				f.policy.Mode = "promisor"
				f.setPolicy()
				// Invalid local-only destination; guard prevents all object queries.
				f.appendConfig("\n[extensions]\npartialClone=b2\n[remote \"b2\"]\npromisor=true\nurl=" + strconv.Quote(filepath.Join(f.area, "absent-local-destination")) + "\n")
			case "promisor-marker":
				metadataWrite(t, filepath.Join(f.repo, ".git", "objects", "pack", "pack-"+strings.Repeat("0", 40)+".promisor"), "")
			case "split-index":
				f.setup("update-index", "--split-index")
			case "sparse-config":
				f.appendConfig("\n[core]\nsparseCheckout=true\n")
			case "gitfile", "metadata-symlink":
				original := filepath.Join(f.repo, ".git")
				dest := filepath.Join(f.area, "owned-external-metadata")
				if err := os.Rename(original, dest); err != nil {
					t.Fatal(err)
				}
				if name == "gitfile" {
					metadataWrite(t, original, "gitdir: "+dest+"\n")
				} else if err := os.Symlink(dest, original); err != nil {
					t.Fatal(err)
				}
			case "linked-worktree":
				linked := filepath.Join(f.area, "linked")
				f.setup("worktree", "add", "-b", "linked", linked)
				f.appendConfig(b2FilterConfig(f.helper, "clean", true))
				// Move only the selected worktree into the fixed proxy policy path.
				if err := os.Rename(f.repo, filepath.Join(f.area, "main-repo")); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(linked, f.repo); err != nil {
					t.Fatal(err)
				}
				metadataWrite(t, filepath.Join(f.repo, "retained.key"), "synthetic filename-only finding\n")
			}
			f.report(binary, partial)
		})
	}
}

func TestB2_ConfigurationMutation(t *testing.T) {
	binary := b2CandidateBinary(t)
	for _, mode := range []string{"mutate-prepare", "mutate-after"} {
		t.Run(mode, func(t *testing.T) {
			f := b2New(t, mode, true, false)
			f.armed = true
			f.policy.Mode = mode
			f.setPolicy()
			f.report(binary, true)
		})
	}
}

func TestB2_PreparedObjectMutation(t *testing.T) {
	f := b2New(t, "prepared-object-mutation", true, false)
	r, err := NewGitRunner(f.repo)
	if err != nil {
		t.Fatal(err)
	}
	v, err := prepareMetadata(f.ctx, f.repo, r, newMetadataBudget(f.ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := v.Close(); err != nil {
			t.Error(err)
		}
	}()
	f.appendConfig(b2FilterConfig(f.helper, "clean", true))
	metadataWrite(t, filepath.Join(f.repo, ".git", "objects", "info", "alternates"), filepath.Join(f.area, "absent-alternate")+"\n")
	if _, err := v.Run(f.ctx, f.repo, metadataStatus...); err != nil {
		t.Fatal(err)
	}
	f.noStart()
	if err := v.verify(); !errors.Is(err, ErrUnsafeGitMetadata) {
		t.Fatal("B2 original metadata mutation undetected", err)
	}
	t.Log("private status used copied policy/objects; source verification refused; START bytes=0")
}

func TestB2_ProductionMetadataBudget(t *testing.T) {
	binary := b2CandidateBinary(t)
	f := b2New(t, "production-byte-budget", true, false)
	for _, suffix := range []string{strings.Repeat("1", 38), strings.Repeat("2", 38), strings.Repeat("3", 38)} {
		path := filepath.Join(f.repo, ".git", "objects", "00", suffix)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(file.Truncate(64<<20), file.Close()); err != nil {
			t.Fatal(err)
		}
	}
	f.report(binary, true)
}
