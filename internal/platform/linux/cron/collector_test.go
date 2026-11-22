//go:build linux

package cron

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestCronCollectorEmitsCronJobs(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "daily-backup")
	if err := os.WriteFile(cronFile, []byte("0 2 * * * root /usr/local/bin/backup.sh\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.SetCronDirs([]string{dir})

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindCronJob && o.Resource == cronFile {
			found = true
			if cmd, _ := o.Attr(models.AttrCronCommand); cmd == "" {
				t.Fatal("cron_command attribute should be populated")
			}
		}
	}
	if !found {
		t.Fatal("expected identity.cron_job observation for cron file")
	}
}

func TestCronCollectorSkipsMissingDir(t *testing.T) {
	c := NewCollector()
	c.SetCronDirs([]string{filepath.Join(t.TempDir(), "does-not-exist")})

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(obs) != 0 {
		t.Fatalf("expected no observations for missing cron dir, got %d", len(obs))
	}
}

func TestCronCollectorPermissionDeniedUnavailable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cron-restricted")
	if err := os.Mkdir(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)

	c := NewCollector()
	c.SetCronDirs([]string{dir})

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindCronJob && o.Status == models.StatusUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatal("expected unavailable identity.cron_job observation for unreadable cron dir")
	}
}
