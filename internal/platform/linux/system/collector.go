//go:build linux

// Package system collects host, kernel and security-control observations.
package system

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

// collectorName is the provenance recorded on every observation.
const collectorName = "linux.system"

// Collector gathers host identity, security modules and sysctl state.
// It never requires root: unreadable sources become explicitly unavailable
// observations instead of silent gaps.
type Collector struct {
	procRoot string
	sysRoot  string
	now      func() time.Time
}

// NewCollector returns a collector reading from the live /proc and /sys.
func NewCollector() *Collector {
	return &Collector{
		procRoot: "/proc",
		sysRoot:  "/sys",
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	now := c.now()
	if err := ctx.Err(); err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}

	var observations []models.Observation
	observations = append(observations, c.systemInfo(now))
	observations = append(observations, c.securityControls(now)...)
	observations = append(observations, c.sysctls(now)...)
	observations = append(observations, c.kernelMitigations(now)...)
	return observations, nil
}

func (c *Collector) systemInfo(now time.Time) models.Observation {
	obs := models.NewObservation(models.KindSystemInfo, "host", collectorName, now, nil)

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		obs.Set(models.AttrHostname, hostname)
	} else if err != nil {
		obs.Set(models.AttrHostname, "unknown")
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: err.Error(),
		}
		obs.Status = models.StatusPartial
	}

	obs.Set(models.AttrArchitecture, runtime.GOARCH)
	if release, version, err := uname(); err == nil {
		obs.Set(models.AttrKernelRelease, release)
		obs.Set(models.AttrKernelVersion, version)
	} else {
		obs.Set(models.AttrKernelRelease, "unknown")
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: err.Error(),
		}
		obs.Status = models.StatusPartial
	}

	release := readOSRelease("/etc/os-release")
	if release == nil {
		release = readOSRelease("/usr/lib/os-release")
	}
	if release != nil {
		obs.Set(models.AttrOSID, release["ID"])
		obs.Set(models.AttrOSName, release["NAME"])
		obs.Set(models.AttrOSVersion, release["VERSION_ID"])
	}

	container, runtimeName := detectContainer()
	obs.Set(models.AttrContainer, boolString(container))
	if runtimeName != "" {
		obs.Set(models.AttrContainerRuntime, runtimeName)
	}
	obs.Set(models.AttrCgroupVersion, cgroupVersion(c.sysRoot))

	if lsms := readLSMList(c.sysRoot); len(lsms) > 0 {
		obs.Set(models.AttrLSMList, strings.Join(lsms, ","))
	}
	return obs
}

func (c *Collector) securityControls(now time.Time) []models.Observation {
	var observations []models.Observation

	lsmPath := c.sysRoot + "/kernel/security/lsm"
	lsms, lsmErr := readTrimmedFile(lsmPath)
	switch {
	case lsmErr == nil && lsms != "":
		for _, lsm := range strings.Split(lsms, ",") {
			lsm = strings.TrimSpace(lsm)
			if lsm == "" {
				continue
			}
			obs := models.NewObservation(models.KindSecurityControl, "lsm:"+lsm, collectorName, now, nil)
			obs.Set(models.AttrActive, "true")
			obs.Set(models.AttrDetail, lsm)
			obs.Set(models.AttrSource, lsmPath)
			observations = append(observations, obs)
		}
	default:
		obs := models.NewObservation(models.KindSecurityControl, "lsm:list", collectorName, now, nil)
		obs.Status = models.StatusUnavailable
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(lsmErr)),
			Message: "LSM list is not readable; security modules cannot be confirmed",
		}
		obs.Set(models.AttrSource, lsmPath)
		observations = append(observations, obs)
	}

	// SELinux exposes its enforcement state only when the module is enabled.
	selinuxPath := c.sysRoot + "/fs/selinux/enforce"
	if value, err := readTrimmedFile(selinuxPath); err == nil {
		obs := models.NewObservation(models.KindSecurityControl, "selinux", collectorName, now, nil)
		obs.Set(models.AttrActive, "true")
		obs.Set(models.AttrValue, value)
		if value == "1" {
			obs.Set(models.AttrDetail, "enforcing")
		} else {
			obs.Set(models.AttrDetail, "permissive")
		}
		obs.Set(models.AttrSource, selinuxPath)
		observations = append(observations, obs)
	} else if !os.IsNotExist(err) {
		obs := models.NewObservation(models.KindSecurityControl, "selinux", collectorName, now, nil)
		obs.Status = models.StatusUnavailable
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: "SELinux state is not readable",
		}
		obs.Set(models.AttrSource, selinuxPath)
		observations = append(observations, obs)
	}

	// AppArmor advertises enablement through a module parameter.
	apparmorPath := c.sysRoot + "/module/apparmor/parameters/enabled"
	if value, err := readTrimmedFile(apparmorPath); err == nil {
		obs := models.NewObservation(models.KindSecurityControl, "apparmor", collectorName, now, nil)
		obs.Set(models.AttrActive, boolString(value == "Y" || value == "y"))
		obs.Set(models.AttrValue, value)
		obs.Set(models.AttrSource, apparmorPath)
		observations = append(observations, obs)
	} else if !os.IsNotExist(err) {
		obs := models.NewObservation(models.KindSecurityControl, "apparmor", collectorName, now, nil)
		obs.Status = models.StatusUnavailable
		obs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: "AppArmor state is not readable",
		}
		obs.Set(models.AttrSource, apparmorPath)
		observations = append(observations, obs)
	}

	return observations
}

// sysctlKeys is the curated set of security-relevant parameters NULQ records.
// Recording a value is not a judgement: rules decide whether it deviates from
// a documented baseline.
var sysctlKeys = []string{
	"kernel.kptr_restrict",
	"kernel.dmesg_restrict",
	"kernel.yama.ptrace_scope",
	"kernel.unprivileged_bpf_disabled",
	"kernel.unprivileged_userns_clone",
	"kernel.perf_event_paranoid",
	"kernel.randomize_va_space",
	"kernel.suid_dumpable",
	"fs.protected_hardlinks",
	"fs.protected_symlinks",
	"fs.protected_fifos",
	"fs.protected_regular",
}

func (c *Collector) sysctls(now time.Time) []models.Observation {
	observations := make([]models.Observation, 0, len(sysctlKeys))
	for _, key := range sysctlKeys {
		path := c.procRoot + "/sys/" + strings.ReplaceAll(key, ".", "/")
		obs := models.NewObservation(models.KindSysctl, key, collectorName, now, nil)
		obs.Set(models.AttrSource, path)

		value, err := readTrimmedFile(path)
		switch {
		case err == nil:
			obs.Set(models.AttrValue, value)
		case os.IsNotExist(err):
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassNotFound),
				Message: "this kernel does not expose the parameter",
			}
		case os.IsPermission(err):
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassPermissionDenied),
				Message: "reading the parameter is not permitted",
			}
		default:
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassOf(err)),
				Message: err.Error(),
			}
		}
		observations = append(observations, obs)
	}
	return observations
}

// kernelMitigations reads hardware vulnerability mitigations from sysfs.
func (c *Collector) kernelMitigations(now time.Time) []models.Observation {
	vulnDir := c.sysRoot + "/devices/system/cpu/vulnerabilities/"
	entries, err := os.ReadDir(vulnDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []models.Observation{models.UnavailableObservation(
			models.KindKernelMitigation, vulnDir, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()})}
	}

	observations := make([]models.Observation, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := vulnDir + name
		obs := models.NewObservation(models.KindKernelMitigation, name, collectorName, now, nil)
		obs.Set(models.AttrMitigationName, name)
		obs.Set(models.AttrSource, path)

		value, err := readTrimmedFile(path)
		switch {
		case err == nil:
			obs.Set(models.AttrMitigationValue, value)
			obs.Set(models.AttrMitigationStatus, statusForMitigation(value))
		case os.IsNotExist(err):
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassNotFound),
				Message: "mitigation status file does not exist",
			}
		case os.IsPermission(err):
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassPermissionDenied),
				Message: "mitigation status is not readable",
			}
		default:
			obs.Status = models.StatusUnavailable
			obs.Error = &models.ObservationError{
				Class:   string(nulqerr.ClassOf(err)),
				Message: err.Error(),
			}
		}
		observations = append(observations, obs)
	}
	return observations
}

// statusForMitigation normalises a kernel mitigation status string.
func statusForMitigation(value string) string {
	switch strings.TrimSpace(value) {
	case "Not affected":
		return "not_affected"
	case "Vulnerable":
		return "vulnerable"
	default:
		if strings.HasPrefix(value, "Mitigation:") {
			return "mitigation_active"
		}
		if strings.HasPrefix(value, "Vulnerable:") {
			return "vulnerable"
		}
		return "unknown"
	}
}

func readTrimmedFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func readLSMList(sysRoot string) []string {
	value, err := readTrimmedFile(sysRoot + "/kernel/security/lsm")
	if err != nil || value == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func cgroupVersion(sysRoot string) string {
	if _, err := os.Stat(sysRoot + "/fs/cgroup/cgroup.controllers"); err == nil {
		return "v2"
	}
	if _, err := os.Stat(sysRoot + "/fs/cgroup"); err == nil {
		return "v1-or-hybrid"
	}
	return "unknown"
}

// containerMarkers maps filesystem markers to runtime names.
var containerMarkers = []struct {
	path    string
	runtime string
}{
	{"/.dockerenv", "docker"},
	{"/run/.containerenv", "podman"},
	{"/run/systemd/container", "systemd-nspawn"},
}

func detectContainer() (bool, string) {
	for _, marker := range containerMarkers {
		if _, err := os.Stat(marker.path); err == nil {
			if marker.runtime == "systemd-nspawn" {
				if value, err := readTrimmedFile(marker.path); err == nil && value != "" {
					return true, value
				}
			}
			return true, marker.runtime
		}
	}
	for _, path := range []string{"/proc/1/cgroup", "/proc/self/cgroup"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		for _, marker := range []string{"docker", "libpod", "podman", "kubepods", "containerd", "lxc", "garden"} {
			if strings.Contains(content, marker) {
				return true, marker
			}
		}
	}
	return false, ""
}

// readOSRelease parses the shell-style key=value format of os-release(5).
// Malformed lines are skipped; missing files yield nil.
func readOSRelease(path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`)
		}
		if key != "" {
			values[key] = value
		}
	}
	return values
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// uname returns the kernel release and version strings.
func uname() (release, version string, err error) {
	var info syscall.Utsname
	if err := syscall.Uname(&info); err != nil {
		return "", "", err
	}
	return utsString(info.Release), utsString(info.Version), nil
}

func utsString(field [65]int8) string {
	buf := make([]byte, 0, len(field))
	for _, char := range field {
		if char == 0 {
			break
		}
		buf = append(buf, byte(char))
	}
	return string(buf)
}
