//go:build linux

package filesystem

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
)

func writeFixtureFile(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod after creation so the process umask cannot mask the test bits.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func findObservation(observations []models.Observation, kind models.Kind, resource string) (models.Observation, bool) {
	for _, obs := range observations {
		if obs.Kind == kind && obs.Resource == resource {
			return obs, true
		}
	}
	return models.Observation{}, false
}

func TestCollectorDiscoversNotableEntries(t *testing.T) {
	root := t.TempDir()
	suidPath := filepath.Join(root, "usr", "bin", "privtool")
	writeFixtureFile(t, suidPath, 0o755|fs.ModeSetuid)

	worldWritable := filepath.Join(root, "data", "shared")
	if err := os.MkdirAll(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}

	// A directory the current user cannot write to. The symlink itself has
	// mode 0777 on Linux; only the target's permissions are meaningful.
	safePathDir := filepath.Join(root, "usr", "local", "bin")
	if err := os.MkdirAll(safePathDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(safePathDir, 0o555); err != nil {
		t.Fatal(err)
	}
	pathLink := filepath.Join(root, "bin")
	if err := os.Symlink(safePathDir, pathLink); err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(Options{
		Roots:    []string{root},
		PathEnv:  pathLink + ":" + worldWritable,
		MaxFiles: 5000,
	}, nil)

	observations, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	suid, ok := findObservation(observations, models.KindFile, suidPath)
	if !ok {
		t.Fatal("set-user-ID fixture was not observed")
	}
	if !suid.Bool(models.AttrSetUID) || suid.Bool(models.AttrSetGID) {
		t.Fatalf("unexpected SUID attributes: %+v", suid.Attributes)
	}
	if mode, _ := suid.Attr(models.AttrMode); mode != "4755" {
		t.Fatalf("mode = %q, want 4755", mode)
	}

	shared, ok := findObservation(observations, models.KindDirectory, worldWritable)
	if !ok {
		t.Fatal("world-writable directory was not observed")
	}
	if !shared.Bool(models.AttrWorldWritable) || shared.Bool(models.AttrSticky) {
		t.Fatalf("unexpected directory attributes: %+v", shared.Attributes)
	}

	entry, ok := findObservation(observations, models.KindPathEntry, pathLink)
	if !ok {
		t.Fatal("PATH entry was not observed")
	}
	// Regression: the symlink itself has mode 0777 on Linux. Permission
	// semantics must follow the target directory, or every symlinked PATH
	// entry is falsely reported as writable.
	if !entry.Bool(models.AttrSymlink) {
		t.Fatal("PATH symlink was not recorded as a symlink")
	}
	if !entry.Bool(models.AttrIsDirectory) {
		t.Fatal("PATH symlink target should be recognised as a directory")
	}
	if entry.Bool(models.AttrWritableByCurrentUser) {
		t.Fatalf("symlink to a non-writable directory reported writable: %+v", entry.Attributes)
	}

	summary, ok := findObservation(observations, models.KindFilesystemScan, root)
	if !ok {
		t.Fatal("scan summary is missing")
	}
	if summary.Bool(models.AttrTruncated) {
		t.Fatal("scan should not be truncated with a generous budget")
	}
	if summary.Status != models.StatusComplete {
		t.Fatalf("summary status = %q", summary.Status)
	}
}

func TestCollectorMarksTruncatedScansPartial(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, "a"), 0o644)
	writeFixtureFile(t, filepath.Join(root, "b"), 0o644)

	collector := NewCollector(Options{Roots: []string{root}, MaxFiles: 1}, nil)
	observations, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	summary, ok := findObservation(observations, models.KindFilesystemScan, root)
	if !ok {
		t.Fatal("scan summary is missing")
	}
	if !summary.Bool(models.AttrTruncated) || summary.Status != models.StatusPartial {
		t.Fatalf("expected a partial truncated summary, got %+v", summary)
	}
	if summary.Note == "" {
		t.Fatal("a truncated summary must explain itself")
	}
}

func TestReadMountsParsesEscapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	content := "/dev/sda1 /mnt/with\\040space ext4 rw,nosuid 0 0\n" +
		"proc /proc proc rw,nosuid 0 0\n" +
		"malformed line\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	mounts, err := ReadMounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("want 2 parsed mounts, got %d: %+v", len(mounts), mounts)
	}
	if mounts[0].Point != "/mnt/with space" {
		t.Fatalf("octal escape not decoded: %q", mounts[0].Point)
	}
	if !hasOption(mounts[0].Options, "nosuid") {
		t.Fatal("mount options were not parsed")
	}
	if usableMount(mounts[1]) {
		t.Fatal("proc must never be scanned")
	}
}

func TestExcludedPathPrunesNestedSnapshotTrees(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/.snapshots", true},
		{"/.snapshots/36/snapshot/usr/bin/chage", true},
		{"/snapshots", true},
		{"/var/lib/docker/overlay2/abc", true},
		{"/var/lib/lxc/rootfs", true},
		{"/proc/self/ns", true},
		{"/sys/kernel/security", true},
		{"/run/user/1000", true},
		{"/usr/bin", false},
		{"/home/user/snapshots", false},
	}
	for _, tc := range cases {
		if got := excludedPath(tc.path); got != tc.want {
			t.Errorf("excludedPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestUsableMountExcludesSnapshotsAndContainerStorage(t *testing.T) {
	cases := []struct {
		point  string
		fstype string
		want   bool
	}{
		{"/", "btrfs", true},
		{"/home", "btrfs", true},
		{"/tmp", "tmpfs", true},
		{"/.snapshots/12/snapshot", "btrfs", false},
		{"/var/lib/docker/overlay2/x", "overlay", false},
		{"/run/user/1000", "tmpfs", false},
		{"/proc", "proc", false},
		{"/sys/fs/cgroup", "cgroup2", false},
	}
	for _, tc := range cases {
		got := usableMount(Mount{Point: tc.point, FSType: tc.fstype})
		if got != tc.want {
			t.Errorf("usableMount(%s, %s) = %v, want %v", tc.point, tc.fstype, got, tc.want)
		}
	}
}

type fakeFileInfo struct {
	mode fs.FileMode
	uid  uint32
	gid  uint32
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid, Gid: f.gid} }

func TestCanWriteHonoursOwnershipAndMode(t *testing.T) {
	user := Credentials{UID: 1000, GID: 1000, Groups: []uint32{50}}

	cases := []struct {
		name string
		info fakeFileInfo
		want bool
	}{
		{"owner writable", fakeFileInfo{mode: 0o644, uid: 1000, gid: 1000}, true},
		{"owner read-only", fakeFileInfo{mode: 0o444, uid: 1000, gid: 1000}, false},
		{"group writable", fakeFileInfo{mode: 0o660, uid: 0, gid: 50}, true},
		{"group read-only", fakeFileInfo{mode: 0o640, uid: 0, gid: 50}, false},
		{"other writable", fakeFileInfo{mode: 0o777, uid: 0, gid: 0}, true},
		{"sealed", fakeFileInfo{mode: 0o755, uid: 0, gid: 0}, false},
	}
	for _, tc := range cases {
		if got := user.CanWrite(tc.info); got != tc.want {
			t.Errorf("%s: CanWrite = %v, want %v", tc.name, got, tc.want)
		}
	}

	root := Credentials{UID: 0, GID: 0, Root: true}
	if !root.CanWrite(fakeFileInfo{mode: 0o444, uid: 1, gid: 1}) {
		t.Error("root must be treated as able to write regardless of mode")
	}
}

func FuzzUnescapeMountField(f *testing.F) {
	f.Add("/mnt/with\\040space")
	f.Add("\\134backslash")
	f.Add("plain")
	f.Fuzz(func(t *testing.T, value string) {
		// Must never panic and must never increase the length beyond input.
		got := unescapeMountField(value)
		if len(got) > len(value) {
			t.Fatalf("decoded field grew: %q -> %q", value, got)
		}
	})
}
