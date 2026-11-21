//go:build linux

// Package acl parses POSIX access and default ACLs and evaluates effective
// permissions without invoking external tools.
//
// The kernel stores POSIX ACLs in the system.posix_acl_access and
// system.posix_acl_default extended attributes. NULQ reads them with the
// standard library's getxattr syscall, validates the binary representation and
// normalizes the result to text. Raw ACL bytes never leave this package.
package acl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// Status describes whether ACL information was available and trustworthy.
type Status string

const (
	StatusNone        Status = "none"
	StatusPresent     Status = "present"
	StatusUnreadable  Status = "unreadable"
	StatusMalformed   Status = "malformed"
	StatusUnsupported Status = "unsupported"
)

// Access is the explicit result of a permission decision.
type Access string

const (
	Allowed Access = "allowed"
	Denied  Access = "denied"
	Unknown Access = "unknown"
)

// undefinedID is ACL_UNDEFINED_ID, the value the kernel stores for ACL entries
// whose tag does not carry a numeric ID (owner, owning group, mask, other).
const undefinedID uint32 = 0xffffffff

// Tag is a POSIX ACL entry tag.
type Tag uint16

const (
	TagUserObj  Tag = 0x01
	TagUser     Tag = 0x02
	TagGroupObj Tag = 0x04
	TagGroup    Tag = 0x08
	TagMask     Tag = 0x10
	TagOther    Tag = 0x20
)

// Entry is one validated ACL entry.
type Entry struct {
	Tag  Tag
	ID   uint32
	Perm uint16
}

// ACL is a validated POSIX ACL. Entries are kept in canonical order.
type ACL struct {
	Entries []Entry
}

// Snapshot is the normalized ACL state of one path.
type Snapshot struct {
	AccessStatus Status
	Access       ACL
	Mask         uint16
	HasMask      bool
	Default      Status
	DefaultACL   ACL
}

// Attributes returns the observation attributes for this snapshot. Only
// normalized text is exposed; raw xattr bytes are never published.
func (s Snapshot) Attributes() map[string]string {
	attrs := map[string]string{
		"acl_status":         string(s.AccessStatus),
		"acl_default_status": string(s.Default),
	}
	if s.AccessStatus == StatusPresent {
		attrs["acl_access"] = s.Access.Text()
		if s.HasMask {
			attrs["acl_mask"] = PermText(s.Mask)
		}
	}
	if s.Default == StatusPresent {
		attrs["acl_default"] = s.DefaultACL.Text()
	}
	return attrs
}

// Text renders canonical, log-safe ACL text.
func (a ACL) Text() string {
	parts := make([]string, 0, len(a.Entries))
	for _, entry := range a.Entries {
		parts = append(parts, entryText(entry))
	}
	return strings.Join(parts, ",")
}

func entryText(entry Entry) string {
	switch entry.Tag {
	case TagUserObj:
		return "u::" + PermText(entry.Perm)
	case TagUser:
		return "u:" + strconv.FormatUint(uint64(entry.ID), 10) + ":" + PermText(entry.Perm)
	case TagGroupObj:
		return "g::" + PermText(entry.Perm)
	case TagGroup:
		return "g:" + strconv.FormatUint(uint64(entry.ID), 10) + ":" + PermText(entry.Perm)
	case TagMask:
		return "m::" + PermText(entry.Perm)
	case TagOther:
		return "o::" + PermText(entry.Perm)
	default:
		return "?:" + strconv.FormatUint(uint64(entry.ID), 10) + ":" + PermText(entry.Perm)
	}
}

// PermText renders read, write and execute permission bits.
func PermText(perm uint16) string {
	var builder strings.Builder
	if perm&4 != 0 {
		builder.WriteByte('r')
	} else {
		builder.WriteByte('-')
	}
	if perm&2 != 0 {
		builder.WriteByte('w')
	} else {
		builder.WriteByte('-')
	}
	if perm&1 != 0 {
		builder.WriteByte('x')
	} else {
		builder.WriteByte('-')
	}
	return builder.String()
}

// Parse parses the kernel's POSIX ACL xattr format (version 2). It validates
// size, version, tag order, required entries, numeric IDs, permission bits and
// the mask requirement for named entries.
func Parse(data []byte) (ACL, error) {
	if len(data) < 4 {
		return ACL{}, fmt.Errorf("ACL is shorter than its version header")
	}
	version := binary.LittleEndian.Uint32(data[:4])
	if version != 2 {
		return ACL{}, fmt.Errorf("unsupported ACL version %d", version)
	}
	body := data[4:]
	if len(body) == 0 || len(body)%8 != 0 {
		return ACL{}, fmt.Errorf("ACL body length %d is not a sequence of 8-byte entries", len(body))
	}

	entries := make([]Entry, 0, len(body)/8)
	var seen [6]bool
	lastRank := -1
	var named bool
	var mask bool
	for offset := 0; offset < len(body); offset += 8 {
		rawTag := binary.LittleEndian.Uint16(body[offset : offset+2])
		perm := binary.LittleEndian.Uint16(body[offset+2 : offset+4])
		id := binary.LittleEndian.Uint32(body[offset+4 : offset+8])
		tag := Tag(rawTag)
		rank, ok := tagRank(tag)
		if !ok {
			return ACL{}, fmt.Errorf("unknown ACL tag 0x%02x", rawTag)
		}
		if perm&^uint16(7) != 0 {
			return ACL{}, fmt.Errorf("ACL tag 0x%02x has invalid permission bits 0x%x", rawTag, perm)
		}
		if rank < lastRank {
			return ACL{}, fmt.Errorf("ACL entries are not in canonical order")
		}
		lastRank = rank
		if tag != TagUser && tag != TagGroup {
			if seen[rank] {
				return ACL{}, fmt.Errorf("duplicate ACL tag 0x%02x", rawTag)
			}
			seen[rank] = true
		}
		switch tag {
		case TagUserObj, TagGroupObj, TagOther:
			// The kernel fills ACL_UNDEFINED_ID for entries that do not
			// carry an ID; hand-built blobs conventionally use 0. Both are
			// accepted and normalized to 0 so the rendered text is stable.
			if id != 0 && id != undefinedID {
				return ACL{}, fmt.Errorf("base ACL tag 0x%02x has non-zero ID %d", rawTag, id)
			}
			id = 0
		case TagUser, TagGroup:
			if id == 0 || id == undefinedID {
				return ACL{}, fmt.Errorf("named ACL tag 0x%02x has undefined ID", rawTag)
			}
			named = true
		case TagMask:
			mask = true
		}
		entries = append(entries, Entry{Tag: tag, ID: id, Perm: perm})
	}

	if !seen[0] || !seen[2] || !seen[5] {
		return ACL{}, fmt.Errorf("ACL is missing owner, owning-group or other entry")
	}
	if named && !mask {
		return ACL{}, fmt.Errorf("ACL has named entries but no mask")
	}
	acl := ACL{Entries: entries}
	if !mask {
		return acl, nil
	}
	if _, ok := acl.Mask(); !ok {
		return ACL{}, fmt.Errorf("ACL mask is unavailable")
	}
	return acl, nil
}

func tagRank(tag Tag) (int, bool) {
	switch tag {
	case TagUserObj:
		return 0, true
	case TagUser:
		return 1, true
	case TagGroupObj:
		return 2, true
	case TagGroup:
		return 3, true
	case TagMask:
		return 4, true
	case TagOther:
		return 5, true
	}
	return 0, false
}

// Mask returns the ACL mask, if present.
func (a ACL) Mask() (uint16, bool) {
	for _, entry := range a.Entries {
		if entry.Tag == TagMask {
			return entry.Perm, true
		}
	}
	return 0, false
}

func (a ACL) base(tag Tag) (uint16, bool) {
	for _, entry := range a.Entries {
		if entry.Tag == tag {
			return entry.Perm, true
		}
	}
	return 0, false
}

// Read reads and validates the access and default ACLs of path. A missing ACL
// is StatusNone; an unreadable or malformed ACL is never treated as absent.
func Read(path string) Snapshot {
	access, accessStatus := readOne(path, "system.posix_acl_access")
	defaultACL, defaultStatus := readOne(path, "system.posix_acl_default")
	snapshot := Snapshot{AccessStatus: accessStatus, Default: defaultStatus}
	if accessStatus == StatusPresent {
		snapshot.Access = access
		if mask, ok := access.Mask(); ok {
			snapshot.Mask, snapshot.HasMask = mask, true
		}
	}
	if defaultStatus == StatusPresent {
		snapshot.DefaultACL = defaultACL
	}
	return snapshot
}

func readOne(path, name string) (ACL, Status) {
	size, err := syscall.Getxattr(path, name, nil)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ENODATA):
			return ACL{}, StatusNone
		case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
			return ACL{}, StatusUnsupported
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			return ACL{}, StatusUnreadable
		default:
			return ACL{}, StatusUnreadable
		}
	}
	if size <= 0 {
		return ACL{}, StatusMalformed
	}
	buf := make([]byte, size)
	n, err := syscall.Getxattr(path, name, buf)
	if err != nil {
		if errors.Is(err, syscall.ERANGE) {
			return ACL{}, StatusMalformed
		}
		return ACL{}, StatusUnreadable
	}
	parsed, err := Parse(buf[:n])
	if err != nil {
		return ACL{}, StatusMalformed
	}
	return parsed, StatusPresent
}

// Perm is an explicit effective-permission result.
type Perm struct {
	Read  Access
	Write Access
	Exec  Access
}

func evaluateMode(uid, gid uint32, groups []uint32, owner, group uint32, mode uint32) Perm {
	if uid == 0 {
		exec := Denied
		if mode&0o111 != 0 {
			exec = Allowed
		}
		return Perm{Read: Allowed, Write: Allowed, Exec: exec}
	}
	var bits uint32
	switch {
	case uid == owner:
		bits = (mode >> 6) & 7
	case groupMatch(gid, groups, group):
		bits = (mode >> 3) & 7
	default:
		bits = mode & 7
	}
	return permFromBits(bits)
}

// EvaluateFor evaluates a path's effective permissions with the owner and
// owning-group IDs supplied by the filesystem observation. POSIX stores those
// IDs in the inode, not in the ACL, so they must be part of the evaluation.
func EvaluateFor(uid, gid uint32, groups []uint32, owner, group uint32, mode uint32, snapshot Snapshot) Perm {
	switch snapshot.AccessStatus {
	case StatusUnreadable, StatusMalformed:
		return Perm{Read: Unknown, Write: Unknown, Exec: Unknown}
	case StatusPresent:
		return evaluateACLFor(uid, gid, groups, owner, group, mode, snapshot)
	default:
		return evaluateMode(uid, gid, groups, owner, group, mode)
	}
}

func evaluateACLFor(uid, gid uint32, groups []uint32, owner, group uint32, mode uint32, snapshot Snapshot) Perm {
	if uid == 0 {
		exec := Denied
		if mode&0o111 != 0 {
			exec = Allowed
		}
		return Perm{Read: Allowed, Write: Allowed, Exec: exec}
	}
	acl := snapshot.Access
	if uid == owner {
		if perm, ok := acl.base(TagUserObj); ok {
			return permFromBits(uint32(perm))
		}
	}
	for _, entry := range acl.Entries {
		if entry.Tag == TagUser && entry.ID == uid {
			bits := uint32(entry.Perm)
			if snapshot.HasMask {
				bits &= uint32(snapshot.Mask)
			}
			return permFromBits(bits)
		}
	}
	bits := uint32(0)
	matched := false
	if groupMatch(gid, groups, group) {
		if perm, ok := acl.base(TagGroupObj); ok {
			bits |= uint32(perm)
			matched = true
		}
	}
	for _, entry := range acl.Entries {
		if entry.Tag == TagGroup && containsGroup(gid, groups, entry.ID) {
			bits |= uint32(entry.Perm)
			matched = true
		}
	}
	if matched {
		if snapshot.HasMask {
			bits &= uint32(snapshot.Mask)
		}
		return permFromBits(bits)
	}
	if perm, ok := acl.base(TagOther); ok {
		return permFromBits(uint32(perm))
	}
	return Perm{Read: Unknown, Write: Unknown, Exec: Unknown}
}

func permFromBits(bits uint32) Perm {
	access := func(bit uint32) Access {
		if bits&bit != 0 {
			return Allowed
		}
		return Denied
	}
	return Perm{Read: access(4), Write: access(2), Exec: access(1)}
}

func groupMatch(gid uint32, groups []uint32, group uint32) bool {
	if gid == group {
		return true
	}
	return containsGroup(gid, groups, group)
}

func containsGroup(gid uint32, groups []uint32, want uint32) bool {
	if gid == want {
		return true
	}
	for _, group := range groups {
		if group == want {
			return true
		}
	}
	return false
}

// CanCreate reports whether the identity can create an entry in a directory.
func CanCreate(perm Perm) Access {
	return both(perm.Write, perm.Exec)
}

// CanReplaceEntry reports whether the identity can remove or rename an entry
// from a directory, accounting for directory write/execute permission and the
// sticky bit. Replacement of a running process's executable is a separate
// future-execution relationship, not a modification of the loaded image.
func CanReplaceEntry(uid, entryOwner, dirOwner uint32, sticky bool, perm Perm) Access {
	access := both(perm.Write, perm.Exec)
	if access != Allowed {
		return access
	}
	if sticky && uid != 0 && uid != dirOwner && uid != entryOwner {
		return Denied
	}
	return Allowed
}

func both(write, exec Access) Access {
	switch {
	case write == Denied || exec == Denied:
		return Denied
	case write == Allowed && exec == Allowed:
		return Allowed
	default:
		return Unknown
	}
}
