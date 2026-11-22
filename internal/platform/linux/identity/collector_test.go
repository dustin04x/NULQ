//go:build linux

package identity

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestCollectorReportsExecutionContext(t *testing.T) {
	observations, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var contextObs models.Observation
	var memberships int
	for _, obs := range observations {
		switch obs.Kind {
		case models.KindExecutionContext:
			contextObs = obs
		case models.KindGroupMembership:
			memberships++
		}
	}
	if contextObs.ID == "" {
		t.Fatal("execution context observation is missing")
	}
	if euid, _ := contextObs.Attr(models.AttrEUID); euid != strconv.Itoa(os.Geteuid()) {
		t.Fatalf("EUID = %q, want %d", euid, os.Geteuid())
	}
	if username, _ := contextObs.Attr(models.AttrUsername); username == "" {
		t.Fatal("username should be recorded")
	}
	if memberships == 0 {
		t.Fatal("at least the primary group membership must be recorded")
	}
	for _, obs := range observations {
		if obs.Kind != models.KindGroupMembership {
			continue
		}
		if name, _ := obs.Attr(models.AttrGroupName); name == "" {
			t.Fatal("group membership must carry a group name")
		}
		if _, ok := obs.Int(models.AttrGroupGID); !ok {
			t.Fatal("group membership must carry a numeric group ID")
		}
	}
}

func TestCollectorReportsUserAccounts(t *testing.T) {
	c := NewCollector()
	observations, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, obs := range observations {
		if obs.Kind == models.KindUserAccount {
			found = true
			if name, _ := obs.Attr(models.AttrUserName); name == "" {
				t.Fatal("user account must carry a name")
			}
			if uid, _ := obs.Attr(models.AttrUserUID); uid == "" {
				t.Fatal("user account must carry a UID")
			}
			if shell, _ := obs.Attr(models.AttrUserShell); shell == "" {
				t.Fatal("user account must carry a shell")
			}
		}
	}
	if !found {
		t.Fatal("expected at least one identity.user_account observation from /etc/passwd")
	}

	// root must always be present in /etc/passwd
	var rootObs *models.Observation
	for i := range observations {
		if observations[i].Kind == models.KindUserAccount {
			if name, _ := observations[i].Attr(models.AttrUserName); name == "root" {
				rootObs = &observations[i]
				break
			}
		}
	}
	if rootObs == nil {
		t.Fatal("root account must be present in /etc/passwd")
	}
	if uid, _ := rootObs.Attr(models.AttrUserUID); uid != "0" {
		t.Fatalf("root UID = %q, want 0", uid)
	}
}

func TestCollectorUserAccountsCustomPath(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\napp:x:1001:1001:app:/home/app:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.SetPasswdPath(passwd)
	observations, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, obs := range observations {
		if obs.Kind == models.KindUserAccount {
			if name, _ := obs.Attr(models.AttrUserName); name != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) != 2 {
		t.Fatalf("want 2 user accounts, got %d: %v", len(names), names)
	}
}
