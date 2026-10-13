//go:build darwin

package git

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func metadataStatEqual(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	return ok && x.Uid == y.Uid && x.Gid == y.Gid && x.Ctimespec == y.Ctimespec
}
func metadataMatchesStat(info os.FileInfo, s *unix.Stat_t) bool {
	if info == nil {
		return false
	}
	x, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(x.Dev) == uint64(s.Dev) && x.Ino == s.Ino && x.Mode == s.Mode && x.Uid == s.Uid && x.Gid == s.Gid && x.Size == s.Size && x.Mtimespec.Sec == s.Mtim.Sec && x.Mtimespec.Nsec == s.Mtim.Nsec && x.Ctimespec.Sec == s.Ctim.Sec && x.Ctimespec.Nsec == s.Ctim.Nsec
}
func metadataIdentityMatches(info os.FileInfo, s *unix.Stat_t) bool {
	if info == nil {
		return false
	}
	x, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(x.Dev) == uint64(s.Dev) && x.Ino == s.Ino && x.Mode == s.Mode && x.Uid == s.Uid && x.Gid == s.Gid
}
