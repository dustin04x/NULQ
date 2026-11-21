//go:build linux

// Package systemd collects read-only systemd unit security directives.
//
// It reads .service unit files from standard systemd directories and
// normalises security-relevant directives into observation attributes. It
// never starts, stops, enables or disables units and never communicates with
// PID 1 over D-Bus.
package systemd

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

const collectorName = "linux.systemd"

// unitPaths lists systemd unit directories searched in priority order. Only
// .service files are read; other unit types are out of scope for M4.
var unitPaths = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// Options configures the collector.
type Options struct {
	// UnitRoots overrides the default unit directories (for tests).
	UnitRoots []string
}

// Collector reads systemd unit files from disk.
type Collector struct {
	opts Options
	log  *slog.Logger
	now  func() time.Time
}

// NewCollector builds a systemd collector.
func NewCollector(opts Options, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Collector{opts: opts, log: logger, now: func() time.Time { return time.Now().UTC() }}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	now := c.now()
	var observations []models.Observation

	roots := c.opts.UnitRoots
	if len(roots) == 0 {
		roots = unitPaths
	}

	seen := make(map[string]bool)
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return observations, nulqerr.Classify("collect systemd", root, err)
		}
		units, err := readUnitFiles(root, seen)
		if err != nil {
			// A missing unit directory is not an error: not every system
			// ships every systemd directory.
			if os.IsNotExist(err) {
				continue
			}
			observations = append(observations, models.UnavailableObservation(
				models.KindSystemdUnit, root, collectorName, now,
				models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()},
			))
			continue
		}
		observations = append(observations, units...)
	}

	sort.SliceStable(observations, func(i, j int) bool {
		if observations[i].Resource != observations[j].Resource {
			return observations[i].Resource < observations[j].Resource
		}
		return observations[i].ID < observations[j].ID
	})

	return observations, nil
}

// readUnitFiles reads every .service file under root and returns one
// observation per file. seen tracks already-processed paths so overlapping
// directories do not produce duplicates.
func readUnitFiles(root string, seen map[string]bool) ([]models.Observation, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var observations []models.Observation
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if seen[path] {
			continue
		}
		seen[path] = true

		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			observations = append(observations, models.UnavailableObservation(
				models.KindSystemdUnit, path, collectorName, time.Now().UTC(),
				models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()},
			))
			continue
		}

		directives := parseUnitDirectives(string(data))
		obs := models.NewObservation(models.KindSystemdUnit, path, collectorName, time.Now().UTC(), nil)
		obs.Set(models.AttrSystemdUser, directives["User"])
		obs.Set(models.AttrSystemdNoNewPrivileges, directives["NoNewPrivileges"])
		obs.Set(models.AttrSystemdProtectSystem, directives["ProtectSystem"])
		obs.Set(models.AttrSystemdProtectHome, directives["ProtectHome"])
		obs.Set(models.AttrSystemdPrivateTmp, directives["PrivateTmp"])
		obs.Set(models.AttrSystemdCapabilityBoundingSet, directives["CapabilityBoundingSet"])
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok {
			obs.Set("owner_uid", fmt.Sprintf("%d", stat.Uid))
			obs.Set("owner_gid", fmt.Sprintf("%d", stat.Gid))
			obs.Set("mode", modeOctal(info.Mode()))
		}
		observations = append(observations, obs)
	}

	return observations, nil
}

// parseUnitDirectives extracts security-relevant directives from a systemd
// unit file. Only directives appearing under [Service] are considered;
// directives elsewhere are ignored to avoid false matches.
func parseUnitDirectives(content string) map[string]string {
	directives := make(map[string]string)
	inService := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "User", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "CapabilityBoundingSet":
			directives[key] = value
		}
	}
	return directives
}

func modeOctal(m fs.FileMode) string {
	return fmt.Sprintf("%04o", m.Perm())
}
