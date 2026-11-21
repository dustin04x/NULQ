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
	procRoot string
	now      func() time.Time
}

// NewCollector returns a collector for the current process.
func NewCollector() *Collector {
	return &Collector{
		procRoot: "/proc",
		now:      func() time.Time { return time.Now().UTC() },
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

	observations := make([]models.Observation, 0, 1+len(memberships))
	observations = append(observations, contextObs)
	observations = append(observations, memberships...)
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
