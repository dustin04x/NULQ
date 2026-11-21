//go:build linux

package acl

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func header() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, 2); return b }

// entry builds one 8-byte kernel ACL entry. Tags that carry no ID use
// ACL_UNDEFINED_ID, exactly as the kernel writes it.
func entry(tag Tag, perm uint16, id uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], uint16(tag))
	binary.LittleEndian.PutUint16(b[2:4], perm)
	binary.LittleEndian.PutUint32(b[4:8], id)
	return b
}

func minimal(owner, group, other uint16) []byte {
	data := header()
	data = append(data, entry(TagUserObj, owner, undefinedID)...)
	data = append(data, entry(TagGroupObj, group, undefinedID)...)
	data = append(data, entry(TagOther, other, undefinedID)...)
	return data
}

func withMaskAndNamedUser(namedID uint32, namedPerm, mask, owner, group, other uint16) []byte {
	data := header()
	data = append(data, entry(TagUserObj, owner, undefinedID)...)
	data = append(data, entry(TagUser, namedPerm, namedID)...)
	data = append(data, entry(TagGroupObj, group, undefinedID)...)
	data = append(data, entry(TagMask, mask, undefinedID)...)
	data = append(data, entry(TagOther, other, undefinedID)...)
	return data
}

func withMaskAndNamedGroup(namedID uint32, namedPerm, mask, owner, group, other uint16) []byte {
	data := header()
	data = append(data, entry(TagUserObj, owner, undefinedID)...)
	data = append(data, entry(TagGroupObj, group, undefinedID)...)
	data = append(data, entry(TagGroup, namedPerm, namedID)...)
	data = append(data, entry(TagMask, mask, undefinedID)...)
	data = append(data, entry(TagOther, other, undefinedID)...)
	return data
}

func TestParseMinimalACL(t *testing.T) {
	parsed, err := Parse(minimal(7, 5, 4))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Text() != "u::rwx,g::r-x,o::r--" {
		t.Fatalf("text = %q", parsed.Text())
	}
}

func TestParseNamedUserRequiresMask(t *testing.T) {
	data := header()
	data = append(data, entry(TagUserObj, 7, 0)...)
	data = append(data, entry(TagUser, 7, 1001)...)
	data = append(data, entry(TagGroupObj, 5, 0)...)
	data = append(data, entry(TagOther, 4, 0)...)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected missing mask error")
	}
}

func TestParseRejectsMalformedAndUnsupported(t *testing.T) {
	cases := [][]byte{
		{1, 0, 0, 0, 0, 0, 0, 0},
		{3, 0, 0, 0},
		header(),
	}
	for _, input := range cases {
		if _, err := Parse(input); err == nil {
			t.Fatalf("expected error for %v", input)
		}
	}
}

func TestEvaluateOwnerNamedUserGroupMaskAndOther(t *testing.T) {
	// Named user 1001 gets rw- but mask restricts to r--.
	aclNamed, err := Parse(withMaskAndNamedUser(1001, 6, 4, 7, 5, 0))
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{AccessStatus: StatusPresent, Access: aclNamed, HasMask: true, Mask: 4}
	owner := EvaluateFor(1000, 1000, nil, 1000, 1000, 0o750, snap)
	if owner.Write != Allowed || owner.Read != Allowed {
		t.Fatalf("owner = %+v", owner)
	}
	named := EvaluateFor(1001, 1001, nil, 1000, 1000, 0o750, snap)
	if named.Write != Denied || named.Read != Allowed {
		t.Fatalf("named user = %+v, want masked read-only", named)
	}
	other := EvaluateFor(2000, 2000, nil, 1000, 1000, 0o750, snap)
	if other.Read != Denied || other.Write != Denied {
		t.Fatalf("other = %+v", other)
	}
}

func TestEvaluateNamedGroupUnionWithMaskAndSupplementary(t *testing.T) {
	// Owning group grants read, named group 44 grants write, mask allows rw.
	aclGroup, err := Parse(withMaskAndNamedGroup(44, 2, 6, 7, 4, 0))
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{AccessStatus: StatusPresent, Access: aclGroup, HasMask: true, Mask: 6}
	perm := EvaluateFor(2000, 2000, []uint32{44}, 1000, 1000, 0o740, snap)
	if perm.Write != Allowed || perm.Read != Denied {
		t.Fatalf("supplementary named group = %+v, want write allowed/read denied", perm)
	}
	// Membership in the owning group contributes the owning-group entry.
	owning := EvaluateFor(2000, 1000, nil, 1000, 1000, 0o740, snap)
	if owning.Read != Allowed || owning.Write != Denied {
		t.Fatalf("owning group member = %+v", owning)
	}
}

func TestEvaluateUnreadableAndMalformedAreUnknown(t *testing.T) {
	unreadable := EvaluateFor(1000, 1000, nil, 0, 0, 0o644, Snapshot{AccessStatus: StatusUnreadable})
	if unreadable.Write != Unknown || unreadable.Read != Unknown {
		t.Fatalf("unreadable = %+v", unreadable)
	}
	malformed := EvaluateFor(1000, 1000, nil, 0, 0, 0o644, Snapshot{AccessStatus: StatusMalformed})
	if malformed.Write != Unknown {
		t.Fatalf("malformed = %+v", malformed)
	}
}

func TestModeFallbackAndRoot(t *testing.T) {
	perm := EvaluateFor(1001, 1001, nil, 1000, 1000, 0o644, Snapshot{AccessStatus: StatusNone})
	if perm.Write != Denied || perm.Read != Allowed {
		t.Fatalf("mode fallback = %+v", perm)
	}
	root := EvaluateFor(0, 0, nil, 1000, 1000, 0o644, Snapshot{AccessStatus: StatusNone})
	if root.Write != Allowed || root.Read != Allowed {
		t.Fatalf("root = %+v", root)
	}
}

func TestCanReplaceEntryStickySemantics(t *testing.T) {
	rwx := Perm{Read: Allowed, Write: Allowed, Exec: Allowed}
	if CanReplaceEntry(1001, 0, 0, true, rwx) != Denied {
		t.Fatal("sticky dir owned by someone else must protect entries")
	}
	if CanReplaceEntry(1001, 0, 1001, true, rwx) != Allowed {
		t.Fatal("owner of sticky dir may replace entries")
	}
	if CanReplaceEntry(1001, 1001, 0, true, rwx) != Allowed {
		t.Fatal("owner of entry may replace entry")
	}
}

// TestReadLiveXattr exercises the xattr read path end to end: the Errno
// mapping from the kernel is what decides whether a missing ACL is "none" or
// an unreadable ACL is "unknown".
func TestReadLiveXattr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A minimal ACL equivalent to the mode bits is dropped by the kernel
	// (posix_acl_update_mode), so a named user entry is required to keep the
	// xattr stored.
	blob := withMaskAndNamedUser(1001, 6, 6, 7, 5, 4)
	if err := syscall.Setxattr(path, "system.posix_acl_access", blob, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("filesystem cannot store POSIX ACLs here: %v", err)
		}
		t.Fatalf("setxattr: %v", err)
	}
	snapshot := Read(path)
	if snapshot.AccessStatus != StatusPresent {
		t.Fatalf("AccessStatus = %s, want present", snapshot.AccessStatus)
	}
	if got, want := snapshot.Access.Text(), "u::rwx,u:1001:rw-,g::r-x,m::rw-,o::r--"; got != want {
		t.Fatalf("ACL text = %q, want %q", got, want)
	}
	attrs := snapshot.Attributes()
	if attrs["acl_status"] != string(StatusPresent) || attrs["acl_access"] == "" {
		t.Fatalf("attributes = %+v", attrs)
	}
	if attrs["acl_mask"] != "rw-" {
		t.Fatalf("acl_mask = %q, want rw-", attrs["acl_mask"])
	}
	// A present ACL must win over mode 0777: the named user is granted write
	// while other is denied it.
	if perm := EvaluateFor(1001, 1001, nil, 0, 0, 0o777, snapshot); perm.Write != Allowed || perm.Read != Allowed {
		t.Fatalf("named user = %+v, want read/write allowed", perm)
	}
	if perm := EvaluateFor(2000, 2000, nil, 0, 0, 0o777, snapshot); perm.Write != Denied {
		t.Fatalf("other must not inherit mode 0777 when an ACL is present: %+v", perm)
	}
}

// TestReadAbsentACLIsNotUnreadable pins the distinction between an absent ACL
// and an ACL that could not be read.
func TestReadAbsentACLIsNotUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot := Read(path)
	switch snapshot.AccessStatus {
	case StatusNone, StatusUnsupported:
		// Both are documented absence results.
	default:
		t.Fatalf("AccessStatus = %s, want none or unsupported", snapshot.AccessStatus)
	}
	if got := snapshot.Attributes()["acl_status"]; got != string(snapshot.AccessStatus) {
		t.Fatalf("acl_status attribute = %q, want %q", got, snapshot.AccessStatus)
	}
}

// TestReadUnreadablePathStaysUnknown ensures an ACL that cannot be read never
// degrades into a mode-bit answer.
func TestReadUnreadablePathStaysUnknown(t *testing.T) {
	snapshot := Read(filepath.Join(t.TempDir(), "absent"))
	if snapshot.AccessStatus != StatusUnreadable {
		t.Fatalf("AccessStatus = %s, want unreadable", snapshot.AccessStatus)
	}
	perm := EvaluateFor(1001, 1001, nil, 0, 0, 0o777, snapshot)
	if perm.Write != Unknown || perm.Read != Unknown || perm.Exec != Unknown {
		t.Fatalf("unreadable ACL must evaluate to unknown, got %+v", perm)
	}
}

func FuzzParseACL(f *testing.F) {
	f.Add(minimal(7, 5, 4))
	f.Add(withMaskAndNamedUser(1001, 7, 7, 7, 5, 0))
	f.Add([]byte{})
	f.Add([]byte{2, 0, 0, 0, 1, 0, 7, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		Parse(data)
	})
}
