//go:build linux

// Package identity collects the credentials of the running process.
package identity

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

const collectorName = "linux.identity"

// Collector gathers real and effective credentials, supplementary groups,
// the process umask and namespace identifiers.
type Collector struct {
	procRoot   string
	passwdPath string
	now        func() time.Time
}

// NewCollector returns a collector for the current process.
func NewCollector() *Collector {
	return &Collector{
		procRoot:   "/proc",
		passwdPath: "/etc/passwd",
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	if err := ctx.Err(); err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}

	now := c.now()
	uid, gid := os.Getuid(), os.Getgid()
	euid, egid := os.Geteuid(), os.Getegid()

	contextObs := models.NewObservation(
		models.KindExecutionContext,
		fmt.Sprintf("process:%d", os.Getpid()),
		collectorName, now, nil)
	contextObs.Set(models.AttrUID, strconv.Itoa(uid))
	contextObs.Set(models.AttrEUID, strconv.Itoa(euid))
	contextObs.Set(models.AttrGID, strconv.Itoa(gid))
	contextObs.Set(models.AttrEGID, strconv.Itoa(egid))

	username := "unknown"
	if current, err := user.Current(); err == nil {
		username = current.Username
	}
	contextObs.Set(models.AttrUsername, username)

	groups, err := os.Getgroups()
	if err != nil {
		contextObs.Status = models.StatusPartial
		contextObs.Error = &models.ObservationError{
			Class:   string(nulqerr.ClassOf(err)),
			Message: "supplementary groups are not readable",
		}
	}

	groupSet := make(map[int]struct{}, len(groups)+1)
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}
	groupSet[egid] = struct{}{}

	groupIDs := make([]int, 0, len(groupSet))
	for group := range groupSet {
		groupIDs = append(groupIDs, group)
	}
	sortInts(groupIDs)

	names := make([]string, 0, len(groupIDs))
	var memberships []models.Observation
	for _, groupID := range groupIDs {
		name := lookupGroupName(groupID)
		names = append(names, fmt.Sprintf("%s(%d)", name, groupID))

		source := "supplementary"
		if groupID == egid {
			source = "primary"
		}
		membership := models.NewObservation(
			models.KindGroupMembership,
			fmt.Sprintf("group:%s", name),
			collectorName, now, nil)
		membership.Set(models.AttrGroupName, name)
		membership.Set(models.AttrGroupGID, strconv.Itoa(groupID))
		membership.Set(models.AttrSource, source)
		membership.Set(models.AttrUsername, username)
		memberships = append(memberships, membership)
	}
	contextObs.Set(models.AttrGroups, strings.Join(names, ","))

	if umask, err := c.readUmask(); err == nil {
		contextObs.Set(models.AttrUmask, umask)
	} else {
		contextObs.Status = models.StatusPartial
	}

	namespaces := c.namespaces()
	for key, value := range namespaces {
		contextObs.Set(key, value)
	}

	// environment capability assessment
	procAvailable := false
	if _, err := os.Stat(c.procRoot); err == nil {
		procAvailable = true
	}
	contextObs.Set(models.AttrEnvProcAvailable, strconv.FormatBool(procAvailable))
	contextObs.Set(models.AttrEnvRoot, strconv.FormatBool(os.Geteuid() == 0))

	observations := make([]models.Observation, 0, 1+len(memberships))
	observations = append(observations, contextObs)
	observations = append(observations, memberships...)

	accounts, err := c.userAccounts(now)
	if err == nil {
		observations = append(observations, accounts...)
	}

	return observations, nil
}

// SetPasswdPath lets callers override the /etc/passwd path (tests).
func (c *Collector) SetPasswdPath(path string) { c.passwdPath = path }

// userAccounts reads /etc/passwd and emits one observation per account.
// Password hashes are never recorded: only the password status field (x, !,
// locked or present) is captured.
// parsePasswdLine parses a single /etc/passwd line into an observation.
// Returns nil observation for blank/comment lines. Returns an error for malformed lines.
func parsePasswdLine(line string, now time.Time, collector string) (models.Observation, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return models.Observation{}, nil
	}
	if len(line) > 4096 {
		return models.Observation{}, fmt.Errorf("passwd line too long: %d", len(line))
	}
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return models.Observation{}, fmt.Errorf("too few fields: %d", len(fields))
	}
	name := fields[0]
	if name == "" {
		return models.Observation{}, fmt.Errorf("empty username")
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil || uid < 0 {
		return models.Observation{}, fmt.Errorf("invalid uid %q", fields[2])
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil || gid < 0 {
		return models.Observation{}, fmt.Errorf("invalid gid %q", fields[3])
	}
	obs := models.NewObservation(models.KindUserAccount, name, collector, now, nil)
	obs.Set(models.AttrUserName, name)
	obs.Set(models.AttrUserPasswordStatus, fields[1])
	obs.Set(models.AttrUserUID, strconv.Itoa(uid))
	obs.Set(models.AttrUserGID, strconv.Itoa(gid))
	obs.Set(models.AttrUserShell, fields[6])
	if len(fields) > 5 {
		obs.Set(models.AttrUserHome, fields[5])
	}
	return obs, nil
}

func (c *Collector) userAccounts(now time.Time) ([]models.Observation, error) {
	file, err := os.Open(c.passwdPath)
	if err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}
	defer file.Close()

	var observations []models.Observation
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		obs, err := parsePasswdLine(scanner.Text(), now, collectorName)
		if err != nil {
			continue
		}
		if obs.ID == "" && obs.Kind == "" {
			// blank/comment
			continue
		}
		observations = append(observations, obs)
	}
	if err := scanner.Err(); err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}
	return observations, nil
}

func (c *Collector) readUmask() (string, error) {
	file, err := os.Open(c.procRoot + "/self/status")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Umask:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Umask:")), nil
		}
	}
	return "", fmt.Errorf("umask not present in /proc/self/status")
}

// namespaceFiles maps observation attribute keys to /proc namespace entries.
var namespaceFiles = []struct {
	key  string
	name string
}{
	{models.AttrNamespaceMount, "mnt"},
	{models.AttrNamespacePID, "pid"},
	{models.AttrNamespaceNet, "net"},
	{models.AttrNamespaceUser, "user"},
	{models.AttrNamespaceIPC, "ipc"},
	{models.AttrNamespaceUTS, "uts"},
	{models.AttrNamespaceCgroup, "cgroup"},
}

func (c *Collector) namespaces() map[string]string {
	out := make(map[string]string, len(namespaceFiles))
	for _, entry := range namespaceFiles {
		target, err := os.Readlink(c.procRoot + "/self/ns/" + entry.name)
		if err != nil {
			continue
		}
		out[entry.key] = target
	}
	return out
}

func lookupGroupName(gid int) string {
	group, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil || group.Name == "" {
		return "gid-" + strconv.Itoa(gid)
	}
	return group.Name
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// parseGroupLine parses a single /etc/group line.
// Returns nil observation for blank/comment lines.
func parseGroupLine(line string, now time.Time, collector string) (models.Observation, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return models.Observation{}, nil
	}
	if len(line) > 4096 {
		return models.Observation{}, fmt.Errorf("group line too long: %d", len(line))
	}
	fields := strings.Split(line, ":")
	if len(fields) < 3 {
		return models.Observation{}, fmt.Errorf("too few fields: %d", len(fields))
	}
	name := fields[0]
	if name == "" {
		return models.Observation{}, fmt.Errorf("empty group name")
	}
	gid, err := strconv.Atoi(fields[2])
	if err != nil || gid < 0 {
		return models.Observation{}, fmt.Errorf("invalid gid %q", fields[2])
	}
	obs := models.NewObservation(models.KindGroupMembership, name, collector, now, nil)
	obs.Set(models.AttrGroupName, name)
	obs.Set(models.AttrGroupGID, strconv.Itoa(gid))
	if len(fields) >= 4 {
		obs.Set("group_members", fields[3])
	}
	return obs, nil
}

// ProcessNamespace captures namespace identifiers for one visible process.
type ProcessNamespace struct {
	PID   int
	Links map[string]string
}

// CollectProcessNamespaces enumerates visible processes under procRoot and
// reads their namespace links. Processes that disappear or are unreadable are
// skipped without error.
func CollectProcessNamespaces(procRoot string) []ProcessNamespace {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []ProcessNamespace
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		links := map[string]string{}
		for _, ns := range []string{"mnt", "pid", "net", "user", "ipc", "uts", "cgroup"} {
			target, err := os.Readlink(procRoot + "/" + e.Name() + "/ns/" + ns)
			if err != nil {
				continue
			}
			links[ns] = target
		}
		if len(links) == 0 {
			continue
		}
		out = append(out, ProcessNamespace{PID: pid, Links: links})
	}
	// deterministic order by pid
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].PID < out[j-1].PID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
