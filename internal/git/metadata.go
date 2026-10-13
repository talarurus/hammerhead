package git

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MetadataRefusalError deliberately contains no repository-controlled text.
// Reasons are fixed internal categories, never config values, paths or stderr.
type MetadataRefusalError struct{ reason string }

func (e *MetadataRefusalError) Error() string {
	return "Git metadata security admission refused: " + e.reason
}
func (e *MetadataRefusalError) Is(target error) bool { return target == ErrUnsafeGitMetadata }

var ErrUnsafeGitMetadata = errors.New("Git metadata security admission refused")

func refuse(reason string) error { return &MetadataRefusalError{reason: reason} }

const (
	metadataBytes           = 128 << 20
	metadataEntries         = 100000
	metadataDescriptors     = 512 // Includes reserved namespace/child/copy descriptors.
	metadataDuration        = 10 * time.Second
	evaluationDuration      = 30 * time.Second
	metadataOutputBytes     = 16 << 20
	metadataCleanupDuration = 2 * time.Second
)

type metadataBudget struct {
	ctx                                    context.Context
	bytes                                  int64
	entries, descriptors, commands, output int
	maxBytes                               int64
	maxEntries, maxDescriptors             int
	deadline                               time.Time
}

func newMetadataBudget(ctx context.Context) *metadataBudget {
	return &metadataBudget{ctx: ctx, maxBytes: metadataBytes, maxEntries: metadataEntries, maxDescriptors: metadataDescriptors, deadline: time.Now().Add(metadataDuration)}
}
func (b *metadataBudget) check() error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if time.Now().After(b.deadline) {
		return refuse("preparation deadline")
	}
	if b.bytes > b.maxBytes || b.entries > b.maxEntries || b.descriptors > b.maxDescriptors {
		return refuse("resource budget")
	}
	return nil
}

// A metadataView is the only capability accepted by the process runner. It is
// private, not constructible by other packages, and invalid after Close.
type metadataView struct {
	allocation, dir, root, home string
	runner                      *GitRunner
	budget                      *metadataBudget
	source                      *metadataSource
	closed                      bool
	admitted                    bool
	evaluationDeadline          time.Time
	indexInfo                   os.FileInfo
	indexHash                   [32]byte
}

func (v *metadataView) Run(ctx context.Context, dir string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v == nil || v.closed || !v.admitted || !queryAllowed(args) {
		return "", refuse("query capability")
	}
	if dir != v.root {
		selected, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", refuse("query directory")
		}
		rel, err := filepath.Rel(v.root, selected)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return "", refuse("query directory")
		}
		dir = selected
	}
	if len(args) > 0 && args[0] == "status" && v.indexInfo != nil {
		path := filepath.Join(v.dir, "index")
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != v.indexInfo.Size() || info.Mode().Perm() != v.indexInfo.Mode().Perm() || !info.ModTime().Equal(v.indexInfo.ModTime()) {
			return "", refuse("copied index identity")
		}
		data, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(data) != v.indexHash {
			return "", refuse("copied index bytes")
		}
	}
	queryCtx, cancel := context.WithDeadline(ctx, v.evaluationDeadline)
	defer cancel()
	out, err := v.runner.runControlled(queryCtx, v, dir, args...)
	if ctx.Err() == nil && queryCtx.Err() != nil {
		return "", ErrGitTimeout
	}
	return out, err
}

func queryAllowed(args []string) bool {
	switch strings.Join(args, "\x00") {
	case "rev-parse\x00--show-toplevel", "symbolic-ref\x00--quiet\x00HEAD", "rev-parse\x00--verify\x00HEAD^{commit}", "status\x00--porcelain=v1\x00-z\x00--ignore-submodules=all":
		return true
	}
	return len(args) == 4 && args[0] == "show-ref" && args[1] == "--verify" && args[2] == "--quiet" && strings.HasPrefix(args[3], "refs/heads/") && !strings.ContainsAny(args[3], "\x00\r\n")
}

// Close removes only the scanner allocation. Its entry manifest was produced
// by the scanner, never by repository enumeration or Git output.
func (v *metadataView) Close() error {
	if v == nil || v.closed {
		return nil
	}
	v.closed = true
	var err error
	if v.source != nil {
		err = v.source.close()
	}
	if v.allocation != "" {
		deadline := time.Now().Add(metadataCleanupDuration)
		if v.source != nil {
			for i := len(v.source.created) - 1; i >= 0; i-- {
				if time.Now().After(deadline) {
					err = errors.Join(err, refuse("private cleanup deadline"))
					break
				}
				if e := os.Remove(v.source.created[i]); e != nil && !os.IsNotExist(e) {
					err = errors.Join(err, refuse("private cleanup"))
				}
			}
		}
		if e := os.Remove(v.allocation); e != nil && !os.IsNotExist(e) {
			err = errors.Join(err, refuse("private cleanup"))
		}
	}
	return err
}

func (v *metadataView) verify() error {
	if v.closed || v.source == nil {
		return refuse("closed capability")
	}
	deadline := v.budget.deadline
	if v.admitted {
		deadline = v.evaluationDeadline
	}
	ctx, cancel := context.WithDeadline(v.budget.ctx, deadline)
	defer cancel()
	err := v.source.verify(ctx)
	if v.budget.ctx.Err() == nil && ctx.Err() != nil {
		return refuse("verification deadline")
	}
	return err
}

var subsectionName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var branchName = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*$`)

// Git's config list preserves dots within a subsection. The first and last
// dots delimit section and variable; intervening dots belong to the name.
// This deliberately supports only a bounded ASCII subset of branch names.
func inertBranchKey(key string) bool {
	name, ok := strings.CutPrefix(key, "branch.")
	if !ok {
		return false
	}
	i := strings.LastIndexByte(name, '.')
	if i < 0 || (name[i+1:] != "remote" && name[i+1:] != "merge") {
		return false
	}
	name = name[:i]
	if len(name) == 0 || len(name) > 255 || strings.HasPrefix(name, "-") || !branchName.MatchString(name) {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

func canonicalBool(value string, implicit bool) (string, bool) {
	if implicit {
		return "true", true
	}
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		return "true", true
	case "false", "no", "off", "0", "":
		return "false", true
	}
	return "", false
}

// Git owns config syntax. This decoder handles only its NUL list wire format
// and the finite B0 semantic policy. Earlier unknown keys refuse even if a
// later assignment would overwrite them.
func projectConfig(out string) (string, error) {
	if out != "" && !strings.HasSuffix(out, "\x00") {
		return "", refuse("configuration records")
	}
	values := map[string]string{}
	for _, record := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		if record == "" {
			continue
		}
		key, value, explicit := strings.Cut(record, "\n")
		low := strings.ToLower(value)
		switch key {
		case "core.repositoryformatversion":
			if !explicit || value != "0" {
				return "", refuse("repository format")
			}
		case "core.bare":
			if b, ok := canonicalBool(value, !explicit); !ok || b != "false" {
				return "", refuse("bare repository")
			}
		case "core.filemode", "core.symlinks", "core.ignorecase", "core.precomposeunicode", "core.trustctime":
			b, ok := canonicalBool(value, !explicit)
			if !ok {
				return "", refuse("configuration boolean")
			}
			values[key] = b
		case "core.checkstat", "core.autocrlf", "core.eol", "core.safecrlf", "status.renames", "diff.renames", "status.showuntrackedfiles":
			allowed := map[string]string{
				"core.checkstat": "default minimal", "core.autocrlf": "true false input", "core.eol": "lf crlf native", "core.safecrlf": "true false warn",
				"status.renames": "true false copies", "diff.renames": "true false copies", "status.showuntrackedfiles": "normal all no",
			}
			if !explicit || !strings.Contains(" "+allowed[key]+" ", " "+low+" ") || strings.ContainsAny(low, " \t\r\n\x00") || low == "" {
				return "", refuse("configuration enum")
			}
			values[key] = low
		case "status.renamelimit", "diff.renamelimit":
			if !explicit || len(value) == 0 || len(value) > 6 || strings.Trim(value, "0123456789") != "" {
				return "", refuse("configuration integer")
			}
			n, e := strconv.Atoi(value)
			if e != nil || n > 100000 {
				return "", refuse("configuration integer")
			}
			values[key] = strconv.Itoa(n)
		case "core.logallrefupdates":
			if _, ok := canonicalBool(value, !explicit); !ok && low != "always" {
				return "", refuse("configuration boolean")
			}
		case "user.name", "user.email": // No identity-producing or writing command is run.
		default:
			section, rest, _ := strings.Cut(key, ".")
			remote, setting, hasSetting := strings.Cut(rest, ".")
			inert := inertBranchKey(key) || (section == "remote" && hasSetting && subsectionName.MatchString(remote) && (setting == "url" || setting == "fetch"))
			inert = inert || (section == "alias" && subsectionName.MatchString(rest))
			// Builtins only; remote/upstream values never enter live config, and
			// no fetch, revision shorthand or alias expansion is requested.
			if !inert {
				return "", refuse("unsupported configuration")
			}
		}
	}
	return generatedConfig(values), nil
}

func generatedConfig(values map[string]string) string {
	out := "[core]\nrepositoryformatversion = 0\nbare = false\nfsmonitor = false\nhooksPath = /dev/null\nattributesFile = /dev/null\nuntrackedCache = false\n"
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		section, name, _ := strings.Cut(k, ".")
		out += fmt.Sprintf("[%s]\n%s = %s\n", section, name, values[k])
	}
	return out
}
