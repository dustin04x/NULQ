//go:build linux

// Package filesystem collects filesystem permission and layout observations.
//
// The collector performs a single bounded traversal per mount point and
// publishes only notable entries: set-owner-ID executables, world-writable
// directories, PATH entries, mounts and a scan summary. Rules consume those
// observations instead of walking the filesystem themselves.
package filesystem

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/platform/linux/acl"
)

// getxattr reads an extended attribute from a file using the Linux getxattr
// syscall. It returns the attribute value or an error.
func getxattr(path, attr string) ([]byte, error) {
	buf := make([]byte, 256)
	for {
		ptr, err := unsafePtr(path)
		if err != nil {
			return nil, err
		}
		attrPtr, err := unsafePtr(attr)
		if err != nil {
			return nil, err
		}
		r0, _, e1 := syscall.Syscall6(
			syscall.SYS_GETXATTR,
			uintptr(ptr),
			uintptr(attrPtr),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			0,
			0,
		)
		if e1 != 0 {
			if e1 == syscall.ERANGE {
				buf = make([]byte, len(buf)*2)
				continue
			}
			return nil, e1
		}
		return buf[:r0], nil
	}
}

func unsafePtr(s string) (uintptr, error) {
	if len(s) == 0 {
		return 0, errors.New("empty string")
	}
	ptr := syscall.StringBytePtr(s)
	return uintptr(unsafe.Pointer(ptr)), nil
}

const collectorName = "linux.filesystem"

// DefaultMaxFiles bounds how many entries are inspected per filesystem root.
// The cap is applied per root so that one large filesystem cannot starve the
// assessment of the others; a root that exceeds it is reported as partial
// with its traversal marked truncated.
const DefaultMaxFiles = 1000000

// Options configures the filesystem collector.
type Options struct {
	// Roots overrides the discovered mount points. Intended for fixtures
	// and targeted assessments; empty means "all usable mounts".
	Roots []string
	// PathEnv is the PATH string to analyse. Empty disables PATH analysis.
	PathEnv string
	// MaxFiles bounds entries visited per root.
	MaxFiles int
}

// Collector discovers filesystem privilege surfaces.
type Collector struct {
	opts  Options
	names *nameCache
	log   *slog.Logger
	now   func() time.Time
}

// NewCollector builds a filesystem collector.
func NewCollector(opts Options, logger *slog.Logger) *Collector {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Collector{
		opts:  opts,
		names: newNameCache(),
		log:   logger,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	now := c.now()
	credentials := CurrentCredentials()
	var observations []models.Observation

	mounts, parseErrors, mountErr := ReadMountInfo("/proc/self/mountinfo")
	usable := usableMounts(mounts)

	explicitRoots := len(c.opts.Roots) > 0
	roots := c.opts.Roots
	if !explicitRoots {
		for _, mount := range usable {
			// Bind-mounted files (for example a swapfile) are real mounts
			// but are not traversable filesystems.
			if info, err := os.Stat(mount.Point); err != nil || !info.IsDir() {
				continue
			}
			roots = append(roots, mount.Point)
		}
		if len(roots) == 0 {
			roots = []string{"/"}
		}
	}
	roots = uniqueSorted(roots)

	if mountErr != nil {
		mountsObs := models.NewObservation(models.KindFilesystemScan, "mounts", collectorName, now, nil)
		mountsObs.Status = models.StatusUnavailable
		mountsObs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(mountErr)),
			Message: "mount table is not readable; filesystem boundaries are unknown",
		}
		observations = append(observations, mountsObs)
	} else {
		for _, mount := range mounts {
			obs := models.NewObservation(models.KindMount, mount.Point, collectorName, now, nil)
			obs.Set(models.AttrMountID, strconv.Itoa(mount.ID))
			obs.Set(models.AttrParentMountID, strconv.Itoa(mount.ParentID))
			obs.Set(models.AttrMajorMinor, fmt.Sprintf("%d:%d", mount.Major, mount.Minor))
			obs.Set(models.AttrMountRoot, mount.Root)
			obs.Set(models.AttrDevice, mount.Device)
			obs.Set(models.AttrMountSource, mount.Device)
			obs.Set(models.AttrFSType, mount.FSType)
			obs.Set(models.AttrMountPoint, mount.Point)
			obs.Set(models.AttrMountOptions, strings.Join(mount.Options, ","))
			obs.Set(models.AttrSuperOptions, strings.Join(mount.SuperOptions, ","))
			obs.Set(models.AttrMountOptional, strings.Join(mount.Optional, ","))
			obs.Set(models.AttrReadOnly, boolString(mount.HasOption("ro")))
			obs.Set(models.AttrNosuid, boolString(mount.HasOption("nosuid")))
			obs.Set(models.AttrNodev, boolString(mount.HasOption("nodev")))
			obs.Set(models.AttrNoexec, boolString(mount.HasOption("noexec")))
			assessed := containsPoint(roots, mount.Point)
			obs.Set(models.AttrAssessed, boolString(assessed))
			if !assessed && !explicitRoots {
				if reason := mountExclusion(mount); reason != "" {
					obs.Set(models.AttrExclusionReason, reason)
				}
			}
			observations = append(observations, obs)
		}
	}
	if len(parseErrors) > 0 && mountErr == nil {
		parseObs := models.NewObservation(models.KindFilesystemScan, "mounts", collectorName, now, nil)
		parseObs.Status = models.StatusPartial
		parseObs.Set("malformed_mount_records", strconv.Itoa(len(parseErrors)))
		parseObs.Note = "some mountinfo records were malformed; their mount boundaries are unknown"
		observations = append(observations, parseObs)
	}

	if c.opts.PathEnv != "" {
		observations = append(observations, c.collectPath(now, credentials, mounts)...)
	}

	// Every separate mount is either scanned as its own root or deliberately
	// excluded. Walking a parent root must never descend into either case, or
	// excluded trees (snapshots, container storage) are silently assessed as
	// part of their parent.
	mountPoints := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		mountPoints[mount.Point] = struct{}{}
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return observations, nulqerr.Classify("scan filesystem", root, err)
		}
		budget := c.opts.MaxFiles
		rootObservations, err := c.scanRoot(ctx, root, mountPoints, mounts, credentials, now, &budget)
		observations = append(observations, rootObservations...)
		if err != nil {
			return observations, err
		}
	}
	return observations, nil
}

// walkSkipDirs are never traversed, even when they appear below a scan root
// that is not a mount point itself.
var walkSkipDirs = map[string]struct{}{
	"/proc": {}, "/sys": {}, "/dev": {}, "/run": {},
}

type scanStats struct {
	files int
	dirs  int
	// errors counts every traversal failure; denied is the subset caused by
	// permission denial. They are separate so coverage reporting can say
	// whether a gap is an access limit or an I/O fault.
	errors    int
	denied    int
	truncated bool
}

func (c *Collector) scanRoot(
	ctx context.Context,
	root string,
	mountPoints map[string]struct{},
	mounts []Mount,
	credentials Credentials,
	now time.Time,
	budget *int,
) ([]models.Observation, error) {
	info, err := os.Lstat(root)
	if err != nil {
		obs := models.NewObservation(models.KindFilesystemScan, root, collectorName, now, nil)
		obs.Status = models.StatusUnavailable
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: "scan root is not accessible",
		}
		return []models.Observation{obs}, nil
	}
	if !info.IsDir() {
		obs := models.NewObservation(models.KindFilesystemScan, root, collectorName, now, nil)
		obs.Status = models.StatusUnavailable
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassUnsupported),
			Message: "scan root is not a directory",
		}
		return []models.Observation{obs}, nil
	}

	var observations []models.Observation
	stats := scanStats{}

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			stats.errors++
			if errors.Is(walkErr, fs.ErrPermission) {
				stats.denied++
			}
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path != root && entry.IsDir() {
			if _, isMount := mountPoints[path]; isMount {
				// Each mount point is scanned as its own root, or excluded.
				return filepath.SkipDir
			}
			if excludedPath(path) {
				return filepath.SkipDir
			}
			if _, skip := walkSkipDirs[path]; skip {
				return filepath.SkipDir
			}
		}

		if *budget <= 0 {
			stats.truncated = true
			return filepath.SkipAll
		}
		*budget--

		fileInfo, err := entry.Info()
		if err != nil {
			stats.errors++
			if errors.Is(err, fs.ErrPermission) {
				stats.denied++
			}
			return nil
		}

		if entry.IsDir() {
			stats.dirs++
			if fileInfo.Mode().Perm()&0o002 != 0 {
				observations = append(observations, c.directoryObservation(path, fileInfo, credentials, mounts, now))
			}
			return nil
		}
		if !fileInfo.Mode().IsRegular() {
			return nil
		}
		stats.files++
		if fileInfo.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			observations = append(observations, c.fileObservation(path, fileInfo, credentials, mounts, now))
		}
		return nil
	})

	summary := models.NewObservation(models.KindFilesystemScan, root, collectorName, now, nil)
	summary.Set(models.AttrFilesVisited, strconv.Itoa(stats.files))
	summary.Set(models.AttrDirsVisited, strconv.Itoa(stats.dirs))
	summary.Set(models.AttrScanErrors, strconv.Itoa(stats.errors))
	summary.Set(models.AttrScanDenied, strconv.Itoa(stats.denied))
	summary.Set(models.AttrTruncated, boolString(stats.truncated))
	if stats.truncated {
		summary.Status = models.StatusPartial
		summary.Note = "filesystem traversal budget exhausted; inode coverage is incomplete"
	}
	observations = append(observations, summary)

	if walkErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return observations, nulqerr.Classify("scan filesystem", root, ctxErr)
		}
		c.log.Debug("filesystem traversal finished with an error", "root", root, "error", walkErr)
	}
	return observations, nil
}

func (c *Collector) fileObservation(path string, info fs.FileInfo, credentials Credentials, mounts []Mount, now time.Time) models.Observation {
	uid, gid, _ := ownership(info)
	obs := models.NewObservation(models.KindFile, path, collectorName, now, nil)
	obs.Set(models.AttrMode, models.ModeOctal(info.Mode()))
	obs.Set(models.AttrModeSymbolic, models.ModeSymbolic(info.Mode()))
	obs.Set(models.AttrSetUID, boolString(info.Mode()&fs.ModeSetuid != 0))
	obs.Set(models.AttrSetGID, boolString(info.Mode()&fs.ModeSetgid != 0))
	obs.Set(models.AttrOwnerUID, strconv.FormatUint(uint64(uid), 10))
	obs.Set(models.AttrOwnerUser, c.names.userName(uid))
	obs.Set(models.AttrGroupGID, strconv.FormatUint(uint64(gid), 10))
	obs.Set(models.AttrGroupName, c.names.groupName(gid))
	obs.Set(models.AttrSizeBytes, strconv.FormatInt(info.Size(), 10))
	obs.Set(models.AttrWritableByCurrentUser, boolString(credentials.CanWrite(info)))
	c.applyPermissions(&obs, path, info, credentials)
	c.applyMount(&obs, path, mounts)
	c.applyFileCapabilities(&obs, path, info)
	return obs
}

func (c *Collector) directoryObservation(path string, info fs.FileInfo, credentials Credentials, mounts []Mount, now time.Time) models.Observation {
	uid, gid, _ := ownership(info)
	obs := models.NewObservation(models.KindDirectory, path, collectorName, now, nil)
	obs.Set(models.AttrMode, models.ModeOctal(info.Mode()))
	obs.Set(models.AttrModeSymbolic, models.ModeSymbolic(info.Mode()))
	obs.Set(models.AttrSticky, boolString(info.Mode()&fs.ModeSticky != 0))
	obs.Set(models.AttrWorldWritable, boolString(info.Mode().Perm()&0o002 != 0))
	obs.Set(models.AttrGroupWritable, boolString(info.Mode().Perm()&0o020 != 0))
	obs.Set(models.AttrOwnerUID, strconv.FormatUint(uint64(uid), 10))
	obs.Set(models.AttrOwnerUser, c.names.userName(uid))
	obs.Set(models.AttrGroupGID, strconv.FormatUint(uint64(gid), 10))
	obs.Set(models.AttrGroupName, c.names.groupName(gid))
	obs.Set(models.AttrWritableByCurrentUser, boolString(credentials.CanWrite(info)))
	c.applyPermissions(&obs, path, info, credentials)
	c.applyMount(&obs, path, mounts)
	return obs
}

func (c *Collector) collectPath(now time.Time, credentials Credentials, mounts []Mount) []models.Observation {
	entries := strings.Split(c.opts.PathEnv, ":")
	observations := make([]models.Observation, 0, len(entries))
	for index, entry := range entries {
		resource := entry
		if resource == "" {
			resource = fmt.Sprintf("<PATH index %d: empty>", index)
		}
		obs := models.NewObservation(models.KindPathEntry, resource, collectorName, now, nil)
		obs.Set(models.AttrPathIndex, strconv.Itoa(index))
		obs.Set(models.AttrPathEntry, entry)

		// Permission semantics follow the final target, because that is what a
		// shell resolves. Lstat is used only to record that the entry is a
		// symlink: the symlink's own 0777 mode must never be treated as a
		// writable directory.
		linkInfo, linkErr := os.Lstat(entry)
		info, err := os.Stat(entry)
		switch {
		case err != nil && os.IsNotExist(err):
			obs.Set(models.AttrPathExists, "false")
			obs.Set(models.AttrIsDirectory, "false")
			if linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
				obs.Set(models.AttrSymlink, "true")
				if target, readErr := os.Readlink(entry); readErr == nil {
					obs.Set(models.AttrSymlinkTarget, target)
					obs.Note = "PATH entry is a dangling symlink"
				}
			}
		case err != nil:
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassOf(err)),
				Message: "PATH entry is not readable",
			}
		default:
			obs.Set(models.AttrPathExists, "true")
			obs.Set(models.AttrIsDirectory, boolString(info.IsDir()))
			if linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
				obs.Set(models.AttrSymlink, "true")
				if target, readErr := os.Readlink(entry); readErr == nil {
					obs.Set(models.AttrSymlinkTarget, target)
				}
			}
			obs.Set(models.AttrMode, models.ModeOctal(info.Mode()))
			obs.Set(models.AttrModeSymbolic, models.ModeSymbolic(info.Mode()))
			uid, gid, _ := ownership(info)
			obs.Set(models.AttrOwnerUID, strconv.FormatUint(uint64(uid), 10))
			obs.Set(models.AttrOwnerUser, c.names.userName(uid))
			obs.Set(models.AttrGroupGID, strconv.FormatUint(uint64(gid), 10))
			obs.Set(models.AttrGroupName, c.names.groupName(gid))
			obs.Set(models.AttrWritableByCurrentUser, boolString(credentials.CanWrite(info)))
			c.applyPermissions(&obs, entry, info, credentials)
			c.applyMount(&obs, entry, mounts)
		}
		observations = append(observations, obs)
	}
	return observations
}

// applyPermissions records normalized ACL state and the effective permission
// result for the assessed credentials. An unreadable or malformed ACL yields
// UNKNOWN, never a mode-bit fallback.
func (c *Collector) applyPermissions(obs *models.Observation, path string, info fs.FileInfo, credentials Credentials) {
	uid, gid, ok := ownership(info)
	if !ok {
		return
	}
	snapshot := acl.Read(path)
	for key, value := range snapshot.Attributes() {
		obs.Set(key, value)
	}
	perm := acl.EvaluateFor(credentials.UID, credentials.GID, credentials.Groups, uid, gid, uint32(info.Mode().Perm()), snapshot)
	obs.Set(models.AttrEffectiveWrite, string(perm.Write))
	obs.Set(models.AttrEffectiveExec, string(perm.Exec))
	switch perm.Write {
	case acl.Allowed:
		obs.Set(models.AttrWritableByCurrentUser, "true")
	case acl.Denied:
		obs.Set(models.AttrWritableByCurrentUser, "false")
	case acl.Unknown:
		// Never claim safety from an unknown ACL: leave mode-bit result only as
		// a recorded attribute is insufficient, so mark unknown explicitly.
		obs.Set(models.AttrWritableByCurrentUser, "unknown")
	}
}

// applyMount attaches the containing mount and its security flags. Missing
// mount metadata is left absent so a rule can distinguish unknown from
// "mounted without the flag".
func (c *Collector) applyMount(obs *models.Observation, path string, mounts []Mount) {
	mount, ok := ResolveMount(path, mounts)
	if !ok {
		return
	}
	obs.Set(models.AttrMountPoint, mount.Point)
	obs.Set(models.AttrMountID, strconv.Itoa(mount.ID))
	obs.Set(models.AttrFSType, mount.FSType)
	obs.Set(models.AttrNosuid, boolString(mount.HasOption("nosuid")))
	obs.Set(models.AttrNodev, boolString(mount.HasOption("nodev")))
	obs.Set(models.AttrNoexec, boolString(mount.HasOption("noexec")))
	obs.Set(models.AttrReadOnly, boolString(mount.HasOption("ro")))
}

// applyFileCapabilities reads the security.capability xattr for privileged
// executables and records permitted, inheritable and effective sets as hex
// strings. Unreadable or absent xattrs are left absent so a rule can
// distinguish unknown from truly unprivileged.
func (c *Collector) applyFileCapabilities(obs *models.Observation, path string, info fs.FileInfo) {
	if !info.Mode().IsRegular() {
		return
	}
	if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) == 0 && info.Mode().Perm()&0o111 == 0 {
		return
	}
	xattr, err := readFileCapabilityXattr(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return
		}
		return
	}
	if xattr == nil {
		return
	}
	obs.Set(models.AttrFileCapPermitted, xattr.Permitted)
	obs.Set(models.AttrFileCapInheritable, xattr.Inheritable)
	obs.Set(models.AttrFileCapEffective, xattr.Effective)
}

// fileCapability is a parsed security.capability xattr value.
type fileCapability struct {
	Permitted   string
	Inheritable string
	Effective   string
}

func readFileCapabilityXattr(path string) (*fileCapability, error) {
	data, err := getxattr(path, "security.capability")
	if err != nil {
		return nil, err
	}
	if len(data) < 20 {
		return nil, os.ErrNotExist
	}
	// v2 magic: 4-byte version (little-endian u32) + 16-byte data.
	version := binary.LittleEndian.Uint32(data[:4])
	if version != 2 {
		return nil, os.ErrNotExist
	}
	data = data[4:]
	permitted := formatCapMask(binary.LittleEndian.Uint64(data[0:8]))
	inheritable := formatCapMask(binary.LittleEndian.Uint64(data[8:16]))
	effective := formatCapMask(binary.LittleEndian.Uint64(data[16:24]))
	return &fileCapability{
		Permitted:   permitted,
		Inheritable: inheritable,
		Effective:   effective,
	}, nil
}

// formatCapMask renders a 64-bit capability mask as a 16-hex-digit string.
func formatCapMask(mask uint64) string {
	return strconv.FormatUint(mask, 16)
}

func containsPoint(points []string, want string) bool {
	for _, point := range points {
		if point == want {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
