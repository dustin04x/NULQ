//go:build linux

package filesystem

import (
	"io/fs"
	"os"
	"syscall"
)

// Credentials are the effective credentials NULQ runs with. Access decisions
// are evaluated against these credentials, never against real UID, because
// the kernel authorises I/O using the effective set.
type Credentials struct {
	UID    uint32
	GID    uint32
	Groups []uint32
	Root   bool
}

// CurrentCredentials reads the effective credentials of this process.
func CurrentCredentials() Credentials {
	rawGroups, _ := os.Getgroups()
	groups := make([]uint32, 0, len(rawGroups))
	for _, gid := range rawGroups {
		groups = append(groups, uint32(gid))
	}
	return Credentials{
		UID:    uint32(os.Geteuid()),
		GID:    uint32(os.Getegid()),
		Groups: groups,
		Root:   os.Geteuid() == 0,
	}
}

func (c Credentials) inGroup(gid uint32) bool {
	if gid == c.GID {
		return true
	}
	for _, group := range c.Groups {
		if group == gid {
			return true
		}
	}
	return false
}

// CanWrite reports whether these credentials could create or remove entries
// in a directory, or write to a file.
//
// Only traditional mode bits are evaluated. POSIX ACLs and capabilities that
// override DAC (such as CAP_DAC_OVERRIDE) are handled conservatively: root is
// treated as able to write, everything else is judged from mode bits. A false
// negative is preferable to a fabricated privilege relationship.
func (c Credentials) CanWrite(info fs.FileInfo) bool {
	if c.Root {
		return true
	}
	mode := info.Mode().Perm()
	owner, group, ok := ownership(info)
	if !ok {
		return mode&0o002 != 0
	}
	switch {
	case owner == c.UID:
		return mode&0o200 != 0
	case c.inGroup(group):
		return mode&0o020 != 0
	default:
		return mode&0o002 != 0
	}
}

func ownership(info fs.FileInfo) (uid, gid uint32, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}
