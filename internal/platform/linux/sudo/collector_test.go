//go:build linux

package sudo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestSudoCollectorEmitsSudoRules(t *testing.T) {
	c := NewCollector()
	c.SetSudoersDir(t.TempDir())

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindSudoRule {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one identity.sudo_rule observation")
	}
}

func TestSudoCollectorReadsSudoersFile(t *testing.T) {
	dir := t.TempDir()
	sudoers := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoers, []byte("root ALL=(ALL) ALL\n%dust ALL=(ALL) NOPASSWD: /usr/bin/apt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.SetSudoersDir(dir)
	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var sudoObs *models.Observation
	for i := range obs {
		if obs[i].Kind == models.KindSudoRule && obs[i].Resource == sudoers {
			sudoObs = &obs[i]
			break
		}
	}
	if sudoObs == nil {
		t.Fatalf("expected identity.sudo_rule observation for %s", sudoers)
	}
	if cmds, _ := sudoObs.Attr(models.AttrSudoCommands); cmds == "" {
		t.Fatal("sudo_commands attribute should be populated")
	}
}

func TestSudoCollectorNonExistentDirUnavailable(t *testing.T) {
	c := NewCollector()
	c.SetSudoersDir(filepath.Join(t.TempDir(), "does-not-exist"))

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindSudoRule && o.Status == models.StatusUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatal("expected unavailable identity.sudo_rule observation for missing sudoers dir")
	}
}
