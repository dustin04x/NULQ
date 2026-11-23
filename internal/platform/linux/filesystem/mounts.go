//go:build linux

package filesystem

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
)

// Mount describes one mountinfo record: a mount in the current mount
// namespace, including its parent relationship and the distinction between
// per-mount options and superblock options.
type Mount struct {
	ID           int
	ParentID     int
	Major        int
	Minor        int
	Root         string
	Device       string
	Point        string
	FSType       string
	Options      []string
	SuperOptions []string
	Optional     []string
}

// ReadMounts parses a mounts file in proc(5) format. It is retained for
// compatibility with callers that only have /proc/mounts; the filesystem
// collector uses mountinfo because it carries IDs, roots and superblock
// options.
func ReadMounts(path string) ([]Mount, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nulqerr.Classify("read mounts", path, err)
	}
	defer file.Close()

	var mounts []Mount
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, Mount{
			Device:  unescapeMountField(fields[0]),
			Point:   unescapeMountField(fields[1]),
			FSType:  fields[2],
			Options: splitOptions(fields[3]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nulqerr.Classify("parse mounts", path, err)
	}
	return mounts, nil
}

// ReadMountInfo reads and parses /proc/self/mountinfo. Malformed individual
// records are returned as classified errors but do not discard valid records:
// a single unparseable mount must not blind the assessment to every other
// mount. A file-level read error is separate and makes all mount boundaries
// unknown.
func ReadMountInfo(path string) ([]Mount, []error, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nulqerr.Classify("read mountinfo", path, err)
	}
	mounts, parseErrors := ParseMountInfo(data)
	return mounts, parseErrors, nil
}

// ParseMountInfo parses mountinfo bytes. Fields are escaped by proc(5) as
// octal sequences, so splitting on spaces is safe before unescaping.
func ParseMountInfo(data []byte) ([]Mount, []error) {
	if len(data) > 4*1024*1024 {
		return nil, []error{fmt.Errorf("mountinfo too large: %d bytes", len(data))}
	}
	var mounts []Mount
	var parseErrors []error
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		mount, err := parseMountInfoLine(line)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("line %d: %w", lineNumber, err))
			continue
		}
		mounts = append(mounts, mount)
	}
	if err := scanner.Err(); err != nil {
		parseErrors = append(parseErrors, fmt.Errorf("scan mountinfo: %w", err))
	}
	return mounts, parseErrors
}

func parseMountInfoLine(line string) (Mount, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return Mount{}, fmt.Errorf("expected at least 10 fields, got %d", len(fields))
	}
	id, err := strconv.Atoi(fields[0])
	if err != nil {
		return Mount{}, fmt.Errorf("invalid mount ID %q", fields[0])
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return Mount{}, fmt.Errorf("invalid parent mount ID %q", fields[1])
	}
	major, minor, err := parseDevice(fields[2])
	if err != nil {
		return Mount{}, err
	}
	separator := -1
	for index := 6; index < len(fields); index++ {
		if fields[index] == "-" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return Mount{}, fmt.Errorf("missing superblock separator")
	}
	if len(fields) < separator+4 {
		return Mount{}, fmt.Errorf("missing filesystem type, source or superblock options")
	}
	if separator+3 > len(fields) {
		return Mount{}, fmt.Errorf("truncated superblock record")
	}
	return Mount{
		ID:           id,
		ParentID:     parent,
		Major:        major,
		Minor:        minor,
		Root:         unescapeMountField(fields[3]),
		Point:        unescapeMountField(fields[4]),
		Options:      splitOptions(fields[5]),
		Optional:     append([]string{}, fields[6:separator]...),
		FSType:       fields[separator+1],
		Device:       unescapeMountField(fields[separator+2]),
		SuperOptions: splitOptions(fields[separator+3]),
	}, nil
}

func parseDevice(value string) (int, int, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid device number %q", value)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major device number %q", value)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor device number %q", value)
	}
	return major, minor, nil
}

func splitOptions(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// HasOption reports whether a mount flag is present in either the per-mount
// or the superblock option set. The kernel can express security flags in
// either set, so assessing only one would produce false assumptions.
func (m Mount) HasOption(name string) bool {
	return hasOption(m.Options, name) || hasOption(m.SuperOptions, name)
}

// AllOptions returns the union of per-mount and superblock options in stable
// order, for evidence display only.
func (m Mount) AllOptions() []string {
	seen := make(map[string]struct{}, len(m.Options)+len(m.SuperOptions))
	out := make([]string, 0, len(m.Options)+len(m.SuperOptions))
	for _, option := range append(append([]string{}, m.Options...), m.SuperOptions...) {
		if _, ok := seen[option]; ok {
			continue
		}
		seen[option] = struct{}{}
		out = append(out, option)
	}
	return out
}

// ResolveMount returns the mount whose mount point is the longest path
// boundary containing path. It never uses a naive string prefix: a path below
// /var/lib/example-old must not resolve to a mount at /var/lib/example.
func ResolveMount(path string, mounts []Mount) (Mount, bool) {
	clean := filepath.Clean(path)
	var best Mount
	found := false
	for _, mount := range mounts {
		point := filepath.Clean(mount.Point)
		if !mountContains(point, clean) {
			continue
		}
		switch {
		case !found:
			best, found = mount, true
		case len(point) > len(filepath.Clean(best.Point)):
			best = mount
		case len(point) == len(filepath.Clean(best.Point)) && mount.ID >= best.ID:
			best = mount
		}
	}
	return best, found
}

func mountContains(point, path string) bool {
	if point == "" {
		return false
	}
	if point == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == point || strings.HasPrefix(path, point+"/")
}

// pseudoFilesystems never contain assessable privilege boundaries.
var pseudoFilesystems = map[string]struct{}{
	"proc": {}, "sysfs": {}, "devtmpfs": {}, "devpts": {}, "cgroup": {}, "cgroup2": {},
	"securityfs": {}, "debugfs": {}, "tracefs": {}, "configfs": {}, "fusectl": {},
	"mqueue": {}, "hugetlbfs": {}, "pstore": {}, "bpf": {}, "autofs": {},
	"rpc_pipefs": {}, "nsfs": {}, "binfmt_misc": {}, "efivarfs": {}, "ramfs": {},
	"squashfs": {}, "fuse.lxcfs": {},
}

// excludedPrefixes are mount points that are part of the kernel's virtual
// surface even when their filesystem type is not in the deny list.
var excludedPrefixes = []string{
	"/proc", "/sys", "/dev/pts", "/dev/mqueue", "/dev/hugepages", "/run/user",
	"/run/credentials", "/run/systemd", "/run/udev", "/run/lock",
	// Container and snapshot storage would otherwise be walked as host
	// filesystems, attributing container internals to the host. Container
	// awareness is an explicit later milestone, not an accidental side effect.
	"/var/lib/docker", "/var/lib/containers", "/var/lib/lxc", "/var/lib/machines",
	"/var/lib/snapd/snap", "/snap",
	// Filesystem snapshots duplicate a whole tree. Traversing them reports
	// the same privileged executables many times over and attributes
	// immutable copies to the live system. They can still be assessed
	// explicitly with --root.
	"/.snapshots", "/snapshots", "/.btrfs/snapshots",
}

func usableMount(mount Mount) bool {
	return mount.Point != "" && mountExclusion(mount) == ""
}

// mountExclusion returns the documented reason a mount point is not assessed
// automatically, or an empty string when it is usable. The reason is published
// on the mount observation so coverage reporting can distinguish a deliberate
// exclusion from an unexpected traversal failure.
func mountExclusion(mount Mount) string {
	switch {
	case mount.Point == "":
		return "invalid_mount"
	case mount.FSType == "tmpfs" && (mount.Point == "/run" || strings.HasPrefix(mount.Point, "/run/")):
		return "runtime_tmpfs"
	case mount.FSType == "tmpfs" && (mount.Point == "/sys" || strings.HasPrefix(mount.Point, "/sys/")):
		return "runtime_tmpfs"
	}
	if _, pseudo := pseudoFilesystems[mount.FSType]; pseudo {
		return "pseudo_filesystem"
	}
	if excludedPath(mount.Point) {
		return "excluded_path"
	}
	return ""
}

// excludedPath reports whether an absolute path belongs to the kernel virtual
// surface, container storage or a snapshot/backup tree. It is used both to
// filter scan roots and to prune those trees when they sit inside another
// root's traversal (for example /.snapshots inside /).
func excludedPath(path string) bool {
	for _, prefix := range excludedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// usableMounts filters and deduplicates mount points.
func usableMounts(mounts []Mount) []Mount {
	seen := make(map[string]struct{}, len(mounts))
	out := make([]Mount, 0, len(mounts))
	for _, mount := range mounts {
		if !usableMount(mount) {
			continue
		}
		if _, ok := seen[mount.Point]; ok {
			continue
		}
		seen[mount.Point] = struct{}{}
		out = append(out, mount)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Point < out[j].Point })
	return out
}

// unescapeMountField decodes the octal escapes proc(5) uses for whitespace,
// backslashes and other special bytes in mount fields.
func unescapeMountField(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			if parsed, err := strconv.ParseUint(value[i+1:i+4], 8, 8); err == nil {
				builder.WriteByte(byte(parsed))
				i += 3
				continue
			}
		}
		builder.WriteByte(value[i])
	}
	return builder.String()
}

func hasOption(options []string, want string) bool {
	for _, option := range options {
		if option == want {
			return true
		}
	}
	return false
}
