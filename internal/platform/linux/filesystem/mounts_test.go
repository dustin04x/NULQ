//go:build linux

package filesystem

import "testing"

func TestParseMountInfoEscapedAndFields(t *testing.T) {
	data := []byte("36 28 0:31 / /var/lib/example\\040old rw,relatime shared:1 - ext4 /dev/sda1 rw,nosuid,nodev\n" +
		"37 36 0:32 /sub /mnt/bind ro,nosuid shared:2 master:1 - tmpfs tmpfs rw,mode=755\n")
	mounts, errs := ParseMountInfo(data)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(mounts) != 2 {
		t.Fatalf("got %d mounts, want 2", len(mounts))
	}
	if mounts[0].Point != "/var/lib/example old" {
		t.Fatalf("escaped point = %q", mounts[0].Point)
	}
	if mounts[0].Root != "/" || mounts[0].ID != 36 || mounts[0].ParentID != 28 || mounts[0].Major != 0 || mounts[0].Minor != 31 {
		t.Fatalf("unexpected mount identity: %+v", mounts[0])
	}
	if mounts[0].FSType != "ext4" || mounts[0].Device != "/dev/sda1" {
		t.Fatalf("unexpected fs/source: %+v", mounts[0])
	}
	if !mounts[0].HasOption("nosuid") || !mounts[0].HasOption("nodev") {
		t.Fatal("per-mount nosuid/nodev not detected")
	}
	if mounts[0].HasOption("noexec") {
		t.Fatal("noexec not present")
	}
	if mounts[1].Root != "/sub" || !mounts[1].HasOption("nosuid") || !mounts[1].HasOption("ro") {
		t.Fatalf("unexpected bind mount: %+v", mounts[1])
	}
	if len(mounts[1].Optional) == 0 {
		t.Fatal("optional fields not preserved")
	}
}

func TestParseMountInfoMalformedRecordsAreIsolated(t *testing.T) {
	data := []byte("bad line\n36 28 0:31 / / rw - ext4 /dev/sda1 rw\n37 nope 0:32 / /x rw - ext4 /dev/sda2 rw\n")
	mounts, errs := ParseMountInfo(data)
	if len(mounts) != 1 || mounts[0].Point != "/" {
		t.Fatalf("mounts = %+v, want only valid root mount", mounts)
	}
	if len(errs) != 2 {
		t.Fatalf("got %d parse errors, want 2: %v", len(errs), errs)
	}
}

func TestResolveMountUsesLongestBoundary(t *testing.T) {
	mounts := []Mount{
		{ID: 1, Point: "/"},
		{ID: 2, Point: "/var/lib/example"},
		{ID: 3, Point: "/var/lib/example-old"},
		{ID: 4, Point: "/var/lib/example/nested"},
	}
	tests := []struct {
		path string
		want string
	}{
		{"/var/lib/example-old/file", "/var/lib/example-old"},
		{"/var/lib/example/file", "/var/lib/example"},
		{"/var/lib/example/nested/file", "/var/lib/example/nested"},
		{"/var/lib/example/nested", "/var/lib/example/nested"},
		{"/var/lib/examples/file", "/"},
		{"/etc/passwd", "/"},
	}
	for _, test := range tests {
		mount, ok := ResolveMount(test.path, mounts)
		if !ok || mount.Point != test.want {
			t.Fatalf("ResolveMount(%q) = (%q,%v), want (%q,true)", test.path, mount.Point, ok, test.want)
		}
	}
}

func TestMountExclusionAndUsable(t *testing.T) {
	cases := []struct {
		mount Mount
		want  string
	}{
		{Mount{Point: "/proc", FSType: "proc"}, "pseudo_filesystem"},
		{Mount{Point: "/run/user/1000", FSType: "tmpfs"}, "runtime_tmpfs"},
		{Mount{Point: "/var/lib/docker", FSType: "ext4"}, "excluded_path"},
		{Mount{Point: "/snapshots/s1", FSType: "btrfs"}, "excluded_path"},
		{Mount{Point: "/home", FSType: "ext4"}, ""},
	}
	for _, tc := range cases {
		if got := mountExclusion(tc.mount); got != tc.want {
			t.Fatalf("mountExclusion(%+v) = %q, want %q", tc.mount, got, tc.want)
		}
	}
}

func FuzzParseMountInfo(f *testing.F) {
	f.Add([]byte("36 28 0:31 / / rw,relatime - ext4 /dev/sda1 rw\n"))
	f.Add([]byte("bad"))
	f.Add([]byte(""))
	f.Add([]byte("1 1 0:0 / /path\\040name ro nosuid shared:1 - tmpfs tmpfs rw\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseMountInfo(data)
	})
}
