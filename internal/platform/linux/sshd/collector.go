//go:build linux

// Package sshd collects SSH daemon configuration and authorized-keys state
// without starting, stopping or connecting to any SSH service.
package sshd

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

const collectorName = "linux.sshd"

// Collector reads sshd_config and checks authorized_keys file writability.
type Collector struct {
	sshdConfigPath string
	passwdPath     string
	now            func() time.Time
}

// NewCollector returns a collector for SSH daemon configuration.
func NewCollector() *Collector {
	return &Collector{
		sshdConfigPath: "/etc/ssh/sshd_config",
		passwdPath:     "/etc/passwd",
		now:            func() time.Time { return time.Now().UTC() },
	}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// SetPasswdPath lets callers override the /etc/passwd path (tests).
func (c *Collector) SetPasswdPath(path string) { c.passwdPath = path }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	now := c.now()
	if err := ctx.Err(); err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}

	var observations []models.Observation

	if obs := c.parseSSHDConfig(now); obs != nil {
		observations = append(observations, *obs)
	}

	observations = append(observations, c.authorizedKeys(now)...)

	return observations, nil
}

// parseSSHDConfig reads sshd_config and emits one observation per directive.
func (c *Collector) parseSSHDConfig(now time.Time) *models.Observation {
	data, err := os.ReadFile(c.sshdConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		unavail := models.UnavailableObservation(
			models.KindSSHDConfig, c.sshdConfigPath, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()})
		return &unavail
	}

	obs := models.NewObservation(models.KindSSHDConfig, c.sshdConfigPath, collectorName, now, nil)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var directives []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		obs.Set(models.AttrSSHDirective+"."+directive, value)
		directives = append(directives, directive+"="+value)
	}
	if len(directives) > 0 {
		obs.Set(models.AttrSSHDirective, strings.Join(directives, "\n"))
	}
	obs.Note = "sshd directives observed: " + strconv.Itoa(len(directives))
	return &obs
}

// authorizedKeys checks ~/.ssh/authorized_keys writability for accounts in /etc/passwd.
func (c *Collector) authorizedKeys(now time.Time) []models.Observation {
	file, err := os.Open(c.passwdPath)
	if err != nil {
		return []models.Observation{models.UnavailableObservation(
			models.KindSSHAuthorizedKeys, "/etc/passwd", collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()})}
	}
	defer file.Close()

	var observations []models.Observation
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		home := fields[5]
		if home == "" || home == "/" {
			continue
		}
		path := filepath.Join(home, ".ssh", "authorized_keys")
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if errors.Is(err, os.ErrPermission) {
				observations = append(observations, models.UnavailableObservation(
					models.KindSSHAuthorizedKeys, path, collectorName, now,
					models.ObservationError{Class: string(nulqerr.ClassPermissionDenied), Message: err.Error()}))
				continue
			}
			continue
		}
		obs := models.NewObservation(models.KindSSHAuthorizedKeys, path, collectorName, now, nil)
		obs.Set(models.AttrAuthKeysPath, path)
		mode := info.Mode()
		// Only group or other write is a risk: owner write is expected.
		groupOrOtherWrite := mode&0o020 != 0 || mode&0o002 != 0
		obs.Set(models.AttrAuthKeysWritable, strconv.FormatBool(groupOrOtherWrite))
		observations = append(observations, obs)
	}
	return observations
}
