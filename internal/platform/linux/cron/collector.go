// Package cron collects cron and at job observations read-only.
package cron

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

const collectorName = "linux.cron"

// Collector reads cron jobs without executing them.
type Collector struct {
	cronDirs []string
	now      func() time.Time
}

// NewCollector returns a collector that reads cron directories.
func NewCollector() *Collector {
	return &Collector{
		cronDirs: []string{
			"/etc/cron.d",
			"/etc/cron.daily",
			"/etc/cron.hourly",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron",
			"/var/spool/cron/crontabs",
		},
		now: func() time.Time { return time.Now().UTC() },
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
	for _, dir := range c.cronDirs {
		entries, err := os.ReadDir(dir)
		switch {
		case err == nil:
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
					continue
				}
				path := filepath.Join(dir, name)
				if obs := c.parseCronFile(path, now); obs != nil {
					observations = append(observations, *obs)
				}
			}
		case errors.Is(err, os.ErrNotExist):
		case errors.Is(err, os.ErrPermission):
			observations = append(observations, models.UnavailableObservation(
				models.KindCronJob, dir, collectorName, now,
				models.ObservationError{Class: string(nulqerr.ClassPermissionDenied), Message: err.Error()}))
		default:
			observations = append(observations, models.UnavailableObservation(
				models.KindCronJob, dir, collectorName, now,
				models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()}))
		}
	}

	return observations, nil
}

// parseCronFile reads one cron file and emits one observation.
func (c *Collector) parseCronFile(path string, now time.Time) *models.Observation {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		unavail := models.UnavailableObservation(
			models.KindCronJob, path, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()})
		return &unavail
	}

	obs := models.NewObservation(models.KindCronJob, path, collectorName, now, nil)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var jobs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		jobs = append(jobs, line)
	}

	if len(jobs) > 0 {
		obs.Set(models.AttrCronCommand, strings.Join(jobs, "\n"))
	}
	obs.Note = fmt.Sprintf("cron job lines observed: %d", len(jobs))
	return &obs
}
