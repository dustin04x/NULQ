//go:build linux

// Package process collects bounded, read-only process metadata from /proc.
//
// It deliberately reads only pid, ppid, comm, numeric credentials, start time,
// kernel-thread state and the executable symlink. It never reads environ,
// cmdline, mem, maps, fd or any file descriptor content, and never executes a
// process or its executable.
package process

import (
	"context"
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

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/platform/linux/acl"
	"github.com/dustin04x/nulq/internal/platform/linux/filesystem"
)

const collectorName = "linux.process"

// DefaultMaxProcesses bounds how many numeric /proc entries are inspected in
// one scan. It is deliberately finite: a hostile PID namespace must not make
// process enumeration unbounded.
const DefaultMaxProcesses = 8192

// Options configures the collector. ProcRoot and MountInfoPath exist for
// synthetic tests; production uses /proc and /proc/self/mountinfo.
type Options struct {
	ProcRoot      string
	MountInfoPath string
	MaxProcesses  int
}

// Collector reads process metadata from a proc filesystem.
type Collector struct {
	opts      Options
	log       *slog.Logger
	now       func() time.Time
	readStart func(string) (string, error)
}

// NewCollector builds a process collector.
func NewCollector(opts Options, logger *slog.Logger) *Collector {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.MountInfoPath == "" {
		opts.MountInfoPath = "/proc/self/mountinfo"
	}
	if opts.MaxProcesses <= 0 {
		opts.MaxProcesses = DefaultMaxProcesses
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Collector{opts: opts, log: logger, now: func() time.Time { return time.Now().UTC() }, readStart: readStartTime}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

type statusInfo struct {
	pid          string
	ppid         string
	name         string
	realUID      uint32
	effectiveID  uint32
	realGID      uint32
	effectiveGID uint32
	groups       []uint32
	kernelThread bool
	uidSeen      bool
	gidSeen      bool
}

// Collect implements interfaces.Collector. A failure to read one process is
// published as an unavailable observation and never aborts the scan. Budget
// exhaustion returns an explicit resource-exhausted error with the partial
// observations retained.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	entries, err := os.ReadDir(c.opts.ProcRoot)
	if err != nil {
		return nil, nulqerr.Classify("read proc", c.opts.ProcRoot, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	credentials := filesystem.CurrentCredentials()
	mounts, _, _ := filesystem.ReadMountInfo(c.opts.MountInfoPath)

	now := c.now()
	var observations []models.Observation
	var inspected int
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return observations, nulqerr.Classify("collect process", c.opts.ProcRoot, err)
		}
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if !numeric(pid) {
			continue
		}
		if inspected >= c.opts.MaxProcesses {
			return observations, nulqerr.New(nulqerr.ClassResourceExhausted, "collect process", c.opts.ProcRoot,
				fmt.Errorf("process budget %d exhausted", c.opts.MaxProcesses))
		}
		inspected++
		observation := c.collectProcess(ctx, pid, credentials, mounts, now)
		if observation != nil {
			observations = append(observations, *observation)
		}
	}
	return observations, nil
}

func (c *Collector) collectProcess(ctx context.Context, pid string, credentials filesystem.Credentials, mounts []filesystem.Mount, now time.Time) *models.Observation {
	resource := "/proc/" + pid
	dir := filepath.Join(c.opts.ProcRoot, pid)
	startBefore, err := c.readStart(filepath.Join(dir, "stat"))
	if err != nil {
		observation := models.UnavailableObservation(models.KindProcess, resource, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: "process stat is not readable"})
		observation.Set(models.AttrPID, pid)
		return &observation
	}

	status, statusErr := readStatus(filepath.Join(dir, "status"))
	if statusErr != nil {
		if ctx.Err() != nil {
			return nil
		}
		observation := models.UnavailableObservation(models.KindProcess, resource, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(statusErr)), Message: "process status is not readable or malformed"})
		observation.Set(models.AttrPID, pid)
		return &observation
	}
	observation := models.NewObservation(models.KindProcess, resource, collectorName, now, nil)
	observation.Set(models.AttrPID, pid)
	observation.Set(models.AttrPPID, status.ppid)
	observation.Set(models.AttrProcessName, status.name)
	observation.Set(models.AttrProcessUID, strconv.FormatUint(uint64(status.realUID), 10))
	observation.Set(models.AttrProcessEUID, strconv.FormatUint(uint64(status.effectiveID), 10))
	observation.Set(models.AttrProcessGID, strconv.FormatUint(uint64(status.realGID), 10))
	observation.Set(models.AttrProcessEGID, strconv.FormatUint(uint64(status.effectiveGID), 10))
	observation.Set(models.AttrProcessStartTime, startBefore)

	groups := make([]string, 0, len(status.groups))
	for _, group := range status.groups {
		groups = append(groups, strconv.FormatUint(uint64(group), 10))
	}
	observation.Set(models.AttrProcessGroups, strings.Join(groups, ","))
	observation.Set(models.AttrKernelThread, boolString(status.kernelThread))

	if status.kernelThread {
		observation.Note = "kernel thread has no userspace executable"
	} else {
		c.addExecutableContext(&observation, dir, credentials, mounts)
	}

	startAfter, err := c.readStart(filepath.Join(dir, "stat"))
	if err != nil || startAfter != startBefore {
		return &models.Observation{
			ID:          models.ObservationID(models.KindProcess, resource),
			Kind:        models.KindProcess,
			Resource:    resource,
			Collector:   collectorName,
			CollectedAt: now,
			Status:      models.StatusPartial,
			Attributes:  map[string]string{models.AttrPID: pid},
			Error: &models.ObservationError{
				Class:   string(nulqerr.ClassNotFound),
				Message: "process disappeared or the PID was reused during collection; attributes were discarded",
			},
		}
	}
	return &observation
}

func (c *Collector) addExecutableContext(observation *models.Observation, dir string, credentials filesystem.Credentials, mounts []filesystem.Mount) {
	link, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		observation.Set(models.AttrExeReadable, "false")
		observation.Status = models.StatusPartial
		observation.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: "executable path is not readable; executable metadata is incomplete",
		}
		return
	}
	observation.Set(models.AttrExeReadable, "true")
	deleted := strings.HasSuffix(link, " (deleted)")
	exePath := strings.TrimSuffix(link, " (deleted)")
	observation.Set(models.AttrExePath, exePath)
	observation.Set(models.AttrExeDeleted, boolString(deleted))
	if deleted {
		observation.Note = "the executable path was deleted after the process started"
	}

	// Stat the proc symlink itself: it follows to the executable even when the
	// directory entry has been unlinked. No file contents are read.
	info, statErr := os.Stat(filepath.Join(dir, "exe"))
	if statErr == nil {
		c.addFileMetadata(observation, info)
		addMountContext(observation, exePath, mounts)
		parent := filepath.Dir(exePath)
		c.addParentContext(observation, parent, credentials, mounts)
	} else {
		observation.Status = models.StatusPartial
		observation.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(statErr)),
			Message: "executable metadata is not readable",
		}
	}
}

func (c *Collector) addFileMetadata(observation *models.Observation, info fs.FileInfo) {
	uid, gid := fileOwnership(info)
	observation.Set(models.AttrExeUID, strconv.FormatUint(uint64(uid), 10))
	observation.Set(models.AttrExeGID, strconv.FormatUint(uint64(gid), 10))
	observation.Set(models.AttrExeMode, models.ModeOctal(info.Mode()))
	observation.Set(models.AttrExeRegular, boolString(info.Mode().IsRegular()))
	observation.Set(models.AttrExeSetUID, boolString(info.Mode()&fs.ModeSetuid != 0))
	observation.Set(models.AttrExeSetGID, boolString(info.Mode()&fs.ModeSetgid != 0))
}

func (c *Collector) addParentContext(observation *models.Observation, parent string, credentials filesystem.Credentials, mounts []filesystem.Mount) {
	info, err := os.Stat(parent)
	if err != nil {
		return
	}
	uid, gid := fileOwnership(info)
	observation.Set(models.AttrParentPath, parent)
	observation.Set(models.AttrParentUID, strconv.FormatUint(uint64(uid), 10))
	observation.Set(models.AttrParentMode, models.ModeOctal(info.Mode()))
	observation.Set(models.AttrParentSticky, boolString(info.Mode()&fs.ModeSticky != 0))
	observation.Set(models.AttrParentWorldWritable, boolString(info.Mode().Perm()&0o002 != 0))
	snapshot := acl.Read(parent)
	attrs := snapshot.Attributes()
	if value, ok := attrs["acl_status"]; ok {
		observation.Set(models.AttrParentACLStatus, value)
	}
	if value, ok := attrs["acl_access"]; ok {
		observation.Set(models.AttrParentACLAccess, value)
	}
	perm := acl.EvaluateFor(credentials.UID, credentials.GID, credentials.Groups, uid, gid, uint32(info.Mode().Perm()), snapshot)
	observation.Set(models.AttrParentEffectiveWrite, string(perm.Write))
	observation.Set(models.AttrParentEffectiveExec, string(perm.Exec))
	// The parent directory's mount context is published under its own keys.
	// Overwriting the executable's mount attributes here would misreport a
	// bind-mounted executable that lives on a different mount than its
	// directory.
	if mount, ok := filesystem.ResolveMount(parent, mounts); ok {
		observation.Set(models.AttrParentMountPoint, mount.Point)
		observation.Set(models.AttrParentNosuid, boolString(mount.HasOption("nosuid")))
		observation.Set(models.AttrParentNoexec, boolString(mount.HasOption("noexec")))
	}
}

func addMountContext(observation *models.Observation, path string, mounts []filesystem.Mount) {
	if mount, ok := filesystem.ResolveMount(path, mounts); ok {
		observation.Set(models.AttrExeMountPoint, mount.Point)
		observation.Set(models.AttrExeNosuid, boolString(mount.HasOption("nosuid")))
		observation.Set(models.AttrExeNoexec, boolString(mount.HasOption("noexec")))
	}
}

func readStartTime(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(data))
	close := strings.LastIndex(line, ")")
	if close < 0 || close+2 >= len(line) {
		return "", fmt.Errorf("malformed stat: missing command terminator")
	}
	fields := strings.Fields(line[close+2:])
	// After the command, field 3 is state; starttime is field 22.
	if len(fields) < 20 {
		return "", fmt.Errorf("malformed stat: %d fields after comm", len(fields))
	}
	value := fields[19]
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return "", fmt.Errorf("malformed starttime %q", value)
	}
	return value, nil
}

func readStatus(path string) (statusInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return statusInfo{}, nulqerr.Classify("read process status", path, err)
	}
	status := statusInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Name":
			status.name = value
		case "PPid":
			status.ppid = value
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) < 2 {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, fmt.Errorf("Uid has fewer than two values"))
			}
			status.realUID, err = parseUint32(fields[0])
			if err != nil {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, err)
			}
			status.effectiveID, err = parseUint32(fields[1])
			if err != nil {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, err)
			}
			status.uidSeen = true
		case "Gid":
			fields := strings.Fields(value)
			if len(fields) < 2 {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, fmt.Errorf("Gid has fewer than two values"))
			}
			status.realGID, err = parseUint32(fields[0])
			if err != nil {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, err)
			}
			status.effectiveGID, err = parseUint32(fields[1])
			if err != nil {
				return statusInfo{}, nulqerr.Malformed("parse process status", path, err)
			}
			status.gidSeen = true
		case "Groups":
			for _, field := range strings.Fields(value) {
				group, parseErr := parseUint32(field)
				if parseErr != nil {
					return statusInfo{}, nulqerr.Malformed("parse process status", path, parseErr)
				}
				status.groups = append(status.groups, group)
			}
		case "Kthread":
			status.kernelThread = value == "1"
		}
	}
	if status.name == "" || status.ppid == "" || !status.uidSeen || !status.gidSeen {
		return statusInfo{}, nulqerr.Malformed("parse process status", path, fmt.Errorf("missing required identity fields"))
	}
	return status, nil
}

func parseUint32(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric identity %q", value)
	}
	return uint32(parsed), nil
}

func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func fileOwnership(info fs.FileInfo) (uint32, uint32) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return stat.Uid, stat.Gid
}
