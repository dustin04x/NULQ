// Package sudo collects sudoers policy observations read-only.
package sudo

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

const collectorName = "linux.sudo"

// Collector reads sudoers policy files without executing sudo.
type Collector struct {
	sudoersDir string
	now        func() time.Time
}

// NewCollector returns a collector that reads sudoers files.
func NewCollector() *Collector {
	return &Collector{
		sudoersDir: "/etc/sudoers.d",
		now:        func() time.Time { return time.Now().UTC() },
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

	if obs := c.parseSudoersFile("/etc/sudoers", now); obs != nil {
		observations = append(observations, *obs)
	}

	entries, err := os.ReadDir(c.sudoersDir)
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
			path := filepath.Join(c.sudoersDir, name)
			if obs := c.parseSudoersFile(path, now); obs != nil {
				observations = append(observations, *obs)
			}
		}
	case errors.Is(err, os.ErrNotExist):
	case errors.Is(err, os.ErrPermission):
		observations = append(observations, models.UnavailableObservation(
			models.KindSudoRule, c.sudoersDir, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassPermissionDenied), Message: err.Error()}))
	default:
		observations = append(observations, models.UnavailableObservation(
			models.KindSudoRule, c.sudoersDir, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()}))
	}

	return observations, nil
}

// parseSudoersFile reads one sudoers file and emits one observation.
func (c *Collector) parseSudoersFile(path string, now time.Time) *models.Observation {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		unavail := models.UnavailableObservation(
			models.KindSudoRule, path, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()})
		return &unavail
	}

	obs := models.NewObservation(models.KindSudoRule, path, collectorName, now, nil)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var rules []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripInlineComment(line)
		if line == "" {
			continue
		}
		rules = append(rules, line)
	}

	if len(rules) > 0 {
		obs.Set(models.AttrSudoCommands, strings.Join(rules, "\n"))
	}
	obs.Note = fmt.Sprintf("sudoers rule lines observed: %d", len(rules))
	return &obs
}

// stripInlineComment removes a trailing # comment that is not inside quotes.
func stripInlineComment(line string) string {
	inSingle := false
	inDouble := false
	for i, ch := range line {
		switch ch {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

// SetSudoersDir lets callers override the sudoers directory (tests).
func (c *Collector) SetSudoersDir(dir string) { c.sudoersDir = dir }
