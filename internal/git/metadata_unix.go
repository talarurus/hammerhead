//go:build darwin || linux

package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/talarurus/hammerhead/internal/fs"
	"golang.org/x/sys/unix"
)

type metadataObservation struct {
	parent       *os.File
	name         string
	info         os.FileInfo
	identityOnly bool
	link         *unix.Stat_t
}
type metadataSource struct {
	budget     *metadataBudget
	dirs       []*os.File
	observed   []metadataObservation
	guard      *fs.PathGuard
	rootHandle *fs.RootHandle
	created    []string
}

func (s *metadataSource) close() error {
	var err error
	for i := len(s.dirs) - 1; i >= 0; i-- {
		err = errors.Join(err, s.dirs[i].Close())
	}
	s.dirs = nil
	if s.guard != nil {
		err = errors.Join(err, s.guard.Close())
	}
	if s.rootHandle != nil {
		err = errors.Join(err, s.rootHandle.Close())
	}
	if err != nil {
		return refuse("descriptor cleanup")
	}
	return nil
}

func sameMetadata(a, b os.FileInfo) bool {
	if !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	// os uses syscall.Stat_t, not unix.Stat_t; platform code supplies the
	// nanosecond change timestamp and ownership comparison.
	return metadataStatEqual(a, b)
}

func (s *metadataSource) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.guard != nil {
		if err := s.guard.Check(); err != nil {
			return refuse("repository namespace changed")
		}
	}
	for _, o := range s.observed {
		if err := ctx.Err(); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstatat(int(o.parent.Fd()), o.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return refuse("metadata changed")
		}
		if o.link != nil {
			x := o.link
			if x.Dev != st.Dev || x.Ino != st.Ino || x.Mode != st.Mode || x.Uid != st.Uid || x.Gid != st.Gid || x.Size != st.Size || x.Mtim != st.Mtim || x.Ctim != st.Ctim {
				return refuse("ambient link changed")
			}
			continue
		}
		if o.identityOnly {
			// Directory contents may change; namespace identity must not.
			if !metadataIdentityMatches(o.info, &st) {
				return refuse("directory namespace changed")
			}
			continue
		}
		if !metadataMatchesStat(o.info, &st) {
			return refuse("metadata changed")
		}
	}
	return nil
}

func (s *metadataSource) openDir(parent *os.File, name string, owned bool) (*os.File, error) {
	if err := s.budget.check(); err != nil {
		return nil, err
	}
	// Sixteen descriptors are reserved for transient copy handles, process
	// pipes/group handling and namespace-watch internals.
	if s.budget.descriptors+17 > s.budget.maxDescriptors {
		return nil, refuse("descriptor budget")
	}
	fd := unix.AT_FDCWD
	if parent != nil {
		fd = int(parent.Fd())
	}
	var before unix.Stat_t
	if err := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, refuse("metadata directory")
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR || (owned && before.Uid != uint32(os.Geteuid())) {
		return nil, refuse("directory type or ownership")
	}
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, refuse("metadata directory")
	}
	f := os.NewFile(uintptr(n), name)
	info, err := f.Stat()
	if err != nil || !metadataMatchesStat(info, &before) {
		f.Close()
		return nil, refuse("directory changed during open")
	}
	s.dirs = append(s.dirs, f)
	s.budget.descriptors++
	if parent != nil {
		s.observed = append(s.observed, metadataObservation{parent: parent, name: name, info: info, identityOnly: true})
	}
	return f, nil
}

func (s *metadataSource) names(f *os.File) ([]string, error) {
	before, err := f.Stat()
	if err != nil {
		return nil, refuse("metadata enumeration")
	}
	var names []string
	for {
		if err := s.budget.check(); err != nil {
			return nil, err
		}
		entries, e := f.ReadDir(32)
		for _, entry := range entries {
			s.budget.entries++
			if err := s.budget.check(); err != nil {
				return nil, err
			}
			names = append(names, entry.Name())
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, refuse("metadata enumeration")
		}
	}
	after, err := f.Stat()
	if err != nil || !sameMetadata(before, after) {
		return nil, refuse("directory changed during enumeration")
	}
	s.observed = append(s.observed, metadataObservation{parent: f, name: ".", info: after})
	return names, nil
}

func (s *metadataSource) copyFile(parent *os.File, name, dest string, limit int64, index bool) (os.FileInfo, error) {
	if err := s.budget.check(); err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, refuse("metadata file")
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Size < 0 || before.Size > limit || before.Size > s.budget.maxBytes-s.budget.bytes {
		return nil, refuse("file type, ownership or size")
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, refuse("metadata file")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !metadataMatchesStat(info, &before) {
		return nil, refuse("file changed during open")
	}
	d, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, refuse("private copy")
	}
	s.created = append(s.created, dest)
	closed := false
	defer func() {
		if !closed {
			d.Close()
		}
	}()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if err := s.budget.check(); err != nil {
			return nil, err
		}
		n, e := f.Read(buf)
		if n > 0 {
			total += int64(n)
			s.budget.bytes += int64(n)
			if total > limit || total > info.Size() {
				return nil, refuse("file grew during copy")
			}
			if err := s.budget.check(); err != nil {
				return nil, err
			}
			if wrote, err := d.Write(buf[:n]); err != nil || wrote != n {
				return nil, refuse("private copy")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, refuse("metadata read")
		}
	}
	after, err := f.Stat()
	if err != nil || !sameMetadata(info, after) || total != info.Size() {
		return nil, refuse("file changed during copy")
	}
	if index {
		// Preserve source permission bits exactly, but refuse writable-by-others
		// or executable indexes; the allocation itself remains mode 0700.
		if info.Mode().Perm()&0133 != 0 {
			return nil, refuse("index permissions")
		}
		if err := d.Chmod(info.Mode().Perm()); err != nil {
			return nil, refuse("index permissions")
		}
		if err := os.Chtimes(dest, info.ModTime(), info.ModTime()); err != nil {
			return nil, refuse("index timestamp precision")
		}
		copied, e := d.Stat()
		if e != nil || copied.Size() != info.Size() || copied.Mode().Perm() != info.Mode().Perm() || !copied.ModTime().Equal(info.ModTime()) {
			return nil, refuse("index timestamp precision")
		}
	}
	if err := d.Close(); err != nil {
		return nil, refuse("private copy close")
	}
	closed = true
	s.observed = append(s.observed, metadataObservation{parent: parent, name: name, info: info})
	return info, nil
}

func (s *metadataSource) discover(selected string) (string, *os.File, error) {
	canonical, err := filepath.EvalSymlinks(selected)
	if err != nil {
		return "", nil, refuse("selected root")
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", nil, refuse("selected root")
	}
	parts := strings.Split(strings.TrimPrefix(canonical, "/"), "/")
	if len(parts)+1 > MaxDetectionAncestorSteps {
		return "", nil, refuse("ancestor budget")
	}
	f, err := s.openDir(nil, "/", false)
	if err != nil {
		return "", nil, err
	}
	chain := []*os.File{f}
	paths := []string{"/"}
	path := "/"
	for _, p := range parts {
		if p == "" {
			continue
		}
		f, err = s.openDir(f, p, false)
		if err != nil {
			return "", nil, err
		}
		path = filepath.Join(path, p)
		chain = append(chain, f)
		paths = append(paths, path)
	}
	// Establish the same namespace observer used by R1 for public wrappers too.
	s.budget.descriptors += len(chain) + 2
	if s.budget.descriptors+16 > s.budget.maxDescriptors {
		return "", nil, refuse("namespace descriptor budget")
	}
	w, err := fs.NewSafeWalker(canonical, nil)
	if err != nil {
		return "", nil, refuse("root observer")
	}
	s.rootHandle, err = w.OpenRoot()
	if err != nil {
		return "", nil, refuse("root observer")
	}
	s.guard, err = s.rootHandle.GuardPath()
	if err != nil {
		return "", nil, refuse("root observer")
	}
	if err := s.budget.check(); err != nil {
		return "", nil, err
	}
	var device uint64
	for i := len(chain) - 1; i >= 0; i-- {
		if err := s.budget.check(); err != nil {
			return "", nil, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(chain[i].Fd()), &st); err != nil {
			return "", nil, refuse("discovery identity")
		}
		if i == len(chain)-1 {
			device = uint64(st.Dev)
		} else if uint64(st.Dev) != device {
			return "", nil, ErrNotARepository
		}
		var marker unix.Stat_t
		e := unix.Fstatat(int(chain[i].Fd()), ".git", &marker, unix.AT_SYMLINK_NOFOLLOW)
		if e == nil {
			if st.Uid != uint32(os.Geteuid()) {
				return "", nil, refuse("worktree ownership")
			}
			gd, e := s.openDir(chain[i], ".git", true)
			return paths[i], gd, e
		}
		if e != unix.ENOENT {
			return "", nil, refuse("repository discovery")
		}
		absent, err := chain[i].Stat()
		if err != nil {
			return "", nil, refuse("discovery absence")
		}
		s.observed = append(s.observed, metadataObservation{parent: chain[i], name: ".", info: absent})
		// Any HEAD plus ordinary bare-repository signature is ambiguous. Do not
		// turn malformed/inaccessible metadata into a clean nonrepository.
		bare := map[string]bool{}
		for _, name := range []string{"HEAD", "objects", "refs", "config"} {
			e := unix.Fstatat(int(chain[i].Fd()), name, &marker, unix.AT_SYMLINK_NOFOLLOW)
			if e != nil && e != unix.ENOENT {
				return "", nil, refuse("bare discovery")
			}
			bare[name] = e == nil
		}
		if bare["HEAD"] && (bare["config"] || (bare["objects"] && bare["refs"])) {
			return "", nil, refuse("bare repository candidate")
		}
	}
	return "", nil, ErrNotARepository
}

func prepareMetadata(ctx context.Context, selected string, r *GitRunner, b *metadataBudget) (_ *metadataView, resultErr error) {
	v := &metadataView{runner: r, budget: b, source: &metadataSource{budget: b}}
	defer func() {
		if resultErr != nil {
			if ctx.Err() != nil {
				resultErr = ctx.Err()
			}
			if errors.Is(resultErr, ErrNotARepository) {
				if e := v.source.verify(ctx); e != nil {
					resultErr = e
				}
			}
			if e := v.Close(); e != nil {
				if errors.Is(resultErr, ErrNotARepository) {
					resultErr = e
				} else {
					resultErr = errors.Join(resultErr, e)
				}
			}
		}
	}()
	root, gd, err := v.source.discover(selected)
	if err != nil {
		return nil, err
	}
	v.root = root
	// A selected subdirectory must not trust an executable/alias owned by the
	// surrounding repository. Recheck the original lookup path, every symlink
	// hop and its final resolution against the discovered actual worktree.
	resolved, e := resolveTrustedGitPath(r.lookupPath, []string{root})
	if e != nil || resolved != r.gitPath {
		return nil, refuse("repository executable namespace")
	}
	top, err := v.source.names(gd)
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	for _, n := range top {
		present[n] = true
		switch n {
		case "HEAD", "config", "index", "packed-refs", "refs", "objects", "info", "hooks", "logs", "branches", "lost-found", "description", "COMMIT_EDITMSG", "ORIG_HEAD", "FETCH_HEAD":
		default:
			return nil, refuse("unsupported metadata layout")
		}
		var st unix.Stat_t
		if e := unix.Fstatat(int(gd.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, refuse("metadata layout type")
		}
		directory := n == "refs" || n == "objects" || n == "info" || n == "hooks" || n == "logs" || n == "branches" || n == "lost-found"
		want := uint32(unix.S_IFREG)
		if directory {
			want = unix.S_IFDIR
		}
		if uint32(st.Mode)&unix.S_IFMT != want || st.Uid != uint32(os.Geteuid()) {
			return nil, refuse("metadata layout type or ownership")
		}
	}
	for _, n := range []string{"HEAD", "config", "refs", "objects"} {
		if !present[n] {
			return nil, refuse("missing metadata")
		}
	}
	// A fixed /tmp allocation avoids a caller TMPDIR inside the repository.
	allocation, err := os.MkdirTemp("/tmp", "hammerhead-git-")
	if err != nil {
		return nil, refuse("private allocation")
	}
	v.allocation = allocation
	canonicalAllocation, e := filepath.EvalSymlinks(allocation)
	if e != nil {
		return nil, refuse("private allocation")
	}
	v.allocation = canonicalAllocation
	if rel, e := filepath.Rel(root, v.allocation); e != nil || (rel != ".." && !strings.HasPrefix(rel, "../")) {
		return nil, refuse("private allocation overlaps worktree")
	}
	v.dir = filepath.Join(v.allocation, "git")
	v.home = filepath.Join(v.allocation, "home")
	for _, p := range []string{v.dir, v.home, filepath.Join(v.home, "xdg"), filepath.Join(v.dir, "refs"), filepath.Join(v.dir, "objects"), filepath.Join(v.dir, "info")} {
		if err := os.Mkdir(p, 0700); err != nil {
			return nil, refuse("private directories")
		}
		v.source.created = append(v.source.created, p)
	}
	if err := os.WriteFile(filepath.Join(v.dir, "config"), []byte(generatedConfig(nil)), 0600); err != nil {
		return nil, refuse("bootstrap configuration")
	}
	v.source.created = append(v.source.created, filepath.Join(v.dir, "config"))
	if _, err := v.source.copyFile(gd, "HEAD", filepath.Join(v.dir, "HEAD"), 1<<20, false); err != nil {
		return nil, err
	}
	if _, err := v.source.copyFile(gd, "config", filepath.Join(v.dir, "input.config"), 1<<20, false); err != nil {
		return nil, err
	}
	parseCtx, cancel := context.WithDeadline(ctx, b.deadline)
	defer cancel()
	out, err := r.runControlled(parseCtx, v, v.dir, "config", "--null", "--list", "--no-includes", "--file", filepath.Join(v.dir, "input.config"))
	if err != nil {
		return nil, preparationError(ctx, err)
	}
	config, err := projectConfig(out)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(v.dir, "config"), []byte(config), 0600); err != nil {
		return nil, refuse("generated configuration")
	}
	if err := v.admitAmbient(parseCtx); err != nil {
		return nil, preparationError(ctx, err)
	}
	metaStart := b.bytes
	for _, n := range []string{"index", "packed-refs"} {
		if present[n] {
			copied, err := v.source.copyFile(gd, n, filepath.Join(v.dir, n), 32<<20, n == "index")
			if err != nil {
				return nil, err
			}
			data, e := os.ReadFile(filepath.Join(v.dir, n))
			if e != nil {
				return nil, refuse("private metadata read")
			}
			if n == "packed-refs" && strings.Contains(string(data), "refs/replace/") {
				return nil, refuse("replacement refs")
			}
			if n == "index" {
				if err := admitIndexEnvelope(data); err != nil {
					return nil, err
				}
				v.indexInfo = copied
				v.indexHash = sha256.Sum256(data)
			}
		}
	}
	rf, err := v.source.openDir(gd, "refs", true)
	if err != nil {
		return nil, err
	}
	if err := v.copyRefs(rf, filepath.Join(v.dir, "refs"), 0); err != nil {
		return nil, err
	}
	if b.bytes-metaStart > 32<<20 {
		return nil, refuse("index and refs budget")
	}
	if present["info"] {
		info, e := v.source.openDir(gd, "info", true)
		if e != nil {
			return nil, e
		}
		names, e := v.source.names(info)
		if e != nil {
			return nil, e
		}
		for _, n := range names {
			if n != "attributes" && n != "exclude" && n != "refs" {
				return nil, refuse("unsupported repository info")
			}
			dest := filepath.Join(v.dir, "info", n)
			// Dumb-transport advertisement, unused by local refs/status; inert.
			if n == "refs" {
				dest = filepath.Join(v.dir, "input.refs")
			}
			if _, e := v.source.copyFile(info, n, dest, 2<<20, false); e != nil {
				return nil, e
			}
		}
	}
	objects, e := v.source.openDir(gd, "objects", true)
	if e != nil {
		return nil, e
	}
	if e := v.copyObjects(objects); e != nil {
		return nil, e
	}
	if present["lost-found"] {
		if e := v.copyLostFound(gd); e != nil {
			return nil, e
		}
	}
	out, err = r.runControlled(parseCtx, v, v.root, "ls-files", "--stage", "--sparse", "-v", "-z")
	if err != nil {
		return nil, preparationError(ctx, err)
	}
	if err := admitIndexListing(out); err != nil {
		return nil, err
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	if err := v.verify(); err != nil {
		return nil, err
	}
	v.admitted = true
	v.evaluationDeadline = time.Now().Add(evaluationDuration)
	return v, nil
}

func preparationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrGitCleanupTimeout) {
		return errors.Join(refuse("preparation command"), ErrGitCleanupTimeout)
	}
	if errors.Is(err, ErrGitTimeout) {
		return errors.Join(refuse("preparation command deadline"), ErrGitTimeout)
	}
	return refuse("preparation command")
}

var looseDir = regexp.MustCompile(`^[0-9a-f]{2}$`)
var looseName = regexp.MustCompile(`^[0-9a-f]{38}$`)
var packName = regexp.MustCompile(`^pack-[0-9a-f]{40}\.(pack|idx|rev|mtimes)$`)
var lostFoundName = regexp.MustCompile(`^[0-9a-f]{40}$`)
var refComponent = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

func (v *metadataView) copyRefs(f *os.File, dest string, depth int) error {
	if depth > 32 {
		return refuse("refs depth")
	}
	names, err := v.source.names(f)
	if err != nil {
		return err
	}
	for _, n := range names {
		if !refComponent.MatchString(n) || n == "replace" || strings.Contains(n, "..") || strings.HasSuffix(n, ".lock") {
			return refuse("unsupported refs namespace")
		}
		var st unix.Stat_t
		if err := unix.Fstatat(int(f.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return refuse("refs metadata")
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			d, e := v.source.openDir(f, n, true)
			if e != nil {
				return e
			}
			if e := os.Mkdir(filepath.Join(dest, n), 0700); e != nil {
				return refuse("private refs")
			}
			v.source.created = append(v.source.created, filepath.Join(dest, n))
			if e := v.copyRefs(d, filepath.Join(dest, n), depth+1); e != nil {
				return e
			}
		} else if _, e := v.source.copyFile(f, n, filepath.Join(dest, n), 1<<20, false); e != nil {
			return e
		}
	}
	return nil
}

func (v *metadataView) copyObjects(f *os.File) error {
	names, err := v.source.names(f)
	if err != nil {
		return err
	}
	for _, n := range names {
		if n != "info" && n != "pack" && !looseDir.MatchString(n) {
			return refuse("object store layout")
		}
		d, e := v.source.openDir(f, n, true)
		if e != nil {
			return e
		}
		files, e := v.source.names(d)
		if e != nil {
			return e
		}
		if n == "info" {
			// packs is dumb-transport advertisement data, never used by these
			// local queries. It is type/owner checked but not copied live.
			for _, name := range files {
				if name != "packs" {
					return refuse("object info or alternates")
				}
				if _, e := v.source.copyFile(d, name, filepath.Join(v.dir, "input.packs"), 1<<20, false); e != nil {
					return e
				}
			}
			continue
		}
		if e := os.Mkdir(filepath.Join(v.dir, "objects", n), 0700); e != nil {
			return refuse("private objects")
		}
		v.source.created = append(v.source.created, filepath.Join(v.dir, "objects", n))
		seen := map[string]bool{}
		for _, name := range files {
			if (n == "pack" && name != "multi-pack-index" && !packName.MatchString(name)) || (n != "pack" && !looseName.MatchString(name)) {
				return refuse("object format or sidecar")
			}
			seen[name] = true
			if _, e := v.source.copyFile(d, name, filepath.Join(v.dir, "objects", n, name), 64<<20, false); e != nil {
				return e
			}
		}
		if n == "pack" {
			for name := range seen {
				if name == "multi-pack-index" || strings.HasSuffix(name, ".rev") || strings.HasSuffix(name, ".mtimes") {
					if e := admitMaintenanceFile(filepath.Join(v.dir, "objects", n, name), name, seen); e != nil {
						return e
					}
				}
				if name == "multi-pack-index" {
					continue
				}
				base := strings.TrimSuffix(name, filepath.Ext(name))
				if !seen[base+".pack"] || !seen[base+".idx"] {
					return refuse("unpaired pack data")
				}
			}
		}
	}
	return nil
}

// Recognize only reviewed SHA-1 maintenance envelopes. Keep their exact bytes
// live in the private store: omitting a malformed MIDX can conceal a Git error.
// Git owns body/offset/checksum interpretation, just as for copied pack/index
// data. This is format admission, not a substitute fsck.
func admitMaintenanceFile(path, name string, packs map[string]bool) error {
	f, err := os.Open(path) // Scanner-created private regular file only.
	if err != nil {
		return refuse("private maintenance read")
	}
	defer f.Close()
	var header [12]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return refuse("maintenance envelope")
	}
	if name == "multi-pack-index" {
		// Standalone v1 is shared by both reviewed Git versions. Incremental
		// chains, v2 and new chunk formats remain outside this profile.
		if string(header[:4]) != "MIDX" || header[4] != 1 || header[5] != 1 || header[7] != 0 {
			return refuse("unsupported multi-pack-index format")
		}
		info, err := f.Stat()
		if err != nil || info.Size() < 32 {
			return refuse("maintenance envelope")
		}
		var chunk [12]byte
		var previous, namesStart, namesEnd uint64
		previousID := ""
		seen := map[string]bool{}
		for i := 0; i <= int(header[6]); i++ {
			if _, err := io.ReadFull(f, chunk[:]); err != nil {
				return refuse("maintenance envelope")
			}
			id := string(chunk[:4])
			offset := binary.BigEndian.Uint64(chunk[4:])
			if offset < uint64(12+(int(header[6])+1)*12) || offset > uint64(info.Size()-20) || offset < previous || offset%4 != 0 || seen[id] {
				return refuse("maintenance chunk framing")
			}
			if previousID == "PNAM" {
				namesStart, namesEnd = previous, offset
			}
			previous, previousID, seen[id] = offset, id, true
			if i == int(header[6]) {
				if id != "\x00\x00\x00\x00" {
					return refuse("maintenance chunk terminator")
				}
			} else {
				switch id {
				case "PNAM", "OIDF", "OIDL", "OOFF", "LOFF", "RIDX", "BTMP":
				default:
					return refuse("unsupported maintenance chunk")
				}
			}
		}
		// MIDX pack names become filesystem paths inside Git. Admit only names
		// of complete ordinary pairs already copied into this private store.
		count := binary.BigEndian.Uint32(header[8:])
		if !seen["PNAM"] || namesEnd < namesStart || count > metadataEntries || namesEnd-namesStart > uint64(count)*54+3 {
			return refuse("multi-pack-index pack names")
		}
		data, err := io.ReadAll(io.NewSectionReader(f, int64(namesStart), int64(namesEnd-namesStart)))
		if err != nil {
			return refuse("private maintenance read")
		}
		for i := uint32(0); i < count; i++ {
			end := bytes.IndexByte(data, 0)
			if end < 0 {
				return refuse("multi-pack-index pack names")
			}
			pack := string(data[:end])
			if !packName.MatchString(pack) || !strings.HasSuffix(pack, ".idx") || !packs[pack] || !packs[strings.TrimSuffix(pack, ".idx")+".pack"] {
				return refuse("multi-pack-index pack names")
			}
			data = data[end+1:]
		}
		if len(data) > 3 || len(bytes.Trim(data, "\x00")) != 0 {
			return refuse("multi-pack-index pack padding")
		}
	} else {
		info, err := f.Stat()
		if err != nil || info.Size() < 52 || (info.Size()-52)%4 != 0 {
			return refuse("maintenance envelope")
		}
		signature := "RIDX"
		if strings.HasSuffix(name, ".mtimes") {
			signature = "MTME"
		}
		if string(header[:4]) != signature || binary.BigEndian.Uint32(header[4:8]) != 1 || binary.BigEndian.Uint32(header[8:]) != 1 {
			return refuse("unsupported maintenance format")
		}
	}
	return nil
}

// fsck --lost-found writes only commit/<SHA-1> and other/<SHA-1>. The fixed
// queries never consume these recovery exports. Check and copy bounded data to
// inert private names, retaining the existing source observations and cleanup.
func (v *metadataView) copyLostFound(gd *os.File) error {
	f, err := v.source.openDir(gd, "lost-found", true)
	if err != nil {
		return err
	}
	names, err := v.source.names(f)
	if err != nil {
		return err
	}
	for _, kind := range names {
		if kind != "commit" && kind != "other" {
			return refuse("unsupported lost-found namespace")
		}
		d, err := v.source.openDir(f, kind, true)
		if err != nil {
			return err
		}
		files, err := v.source.names(d)
		if err != nil {
			return err
		}
		for _, name := range files {
			if !lostFoundName.MatchString(name) {
				return refuse("unsupported lost-found name")
			}
			if _, err := v.source.copyFile(d, name, filepath.Join(v.dir, "input.lost-found."+kind+"."+name), 64<<20, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *metadataView) admitAmbient(ctx context.Context) error {
	// Preserve the installed runtime prefix instead of guessing /etc. This
	// single var query enables only path reporting, never attributes loading.
	out, err := v.runner.runControlled(ctx, v, v.dir, "var", "GIT_ATTR_SYSTEM")
	if err != nil {
		return err
	}
	system, ok := commandLine(out)
	if !ok || !filepath.IsAbs(system) || strings.ContainsAny(system, "\x00\r\n") {
		return refuse("system attributes lookup")
	}
	paths := []string{system}
	if home, ok := os.LookupEnv("HOME"); ok {
		if !filepath.IsAbs(home) {
			return refuse("ambient home uncertainty")
		}
		for _, n := range []string{"ignore", "attributes"} {
			paths = append(paths, filepath.Join(home, ".config", "git", n))
		}
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) {
			return refuse("ambient XDG uncertainty")
		}
		for _, n := range []string{"ignore", "attributes"} {
			paths = append(paths, filepath.Join(xdg, "git", n))
		}
	}
	for _, path := range paths {
		if err := v.source.absentAmbient(path); err != nil {
			return err
		}
	}
	return nil
}

func (s *metadataSource) absentAmbient(path string) error {
	return s.absentAmbientResolved(path, 0)
}
func (s *metadataSource) absentAmbientResolved(path string, links int) error {
	if links > 32 {
		return refuse("ambient symlink budget")
	}
	// Inspect every component without following links. Missing components
	// establish absence; permission errors, symlinks and existing sources refuse.
	f, err := s.openDir(nil, "/", false)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	prefix := "/"
	for i, n := range parts {
		if n == "" || n == "." || n == ".." {
			return refuse("ambient path uncertainty")
		}
		var st unix.Stat_t
		e := unix.Fstatat(int(f.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW)
		if e == unix.ENOENT {
			// Pin absence by observing the parent directory's metadata. The
			// post-evaluation check detects additions, including first components.
			info, e := f.Stat()
			if e != nil {
				return refuse("ambient absence")
			}
			s.observed = append(s.observed, metadataObservation{parent: f, name: ".", info: info})
			return nil
		}
		if e == nil && i < len(parts)-1 && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			buf := make([]byte, 4096)
			nread, e := unix.Readlinkat(int(f.Fd()), n, buf)
			if e != nil || nread == len(buf) {
				return refuse("ambient symlink uncertainty")
			}
			link := st
			s.observed = append(s.observed, metadataObservation{parent: f, name: n, link: &link})
			target := string(buf[:nread])
			if !filepath.IsAbs(target) {
				target = filepath.Join(prefix, target)
			}
			return s.absentAmbientResolved(filepath.Join(append([]string{target}, parts[i+1:]...)...), links+1)
		}
		if e != nil || i == len(parts)-1 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return refuse("ambient policy present or uncertain")
		}
		f, err = s.openDir(f, n, false)
		if err != nil {
			return err
		}
		prefix = filepath.Join(prefix, n)
	}
	return refuse("ambient path uncertainty")
}
