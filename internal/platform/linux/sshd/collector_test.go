//go:build linux

package sshd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestSSHDCollectorParsesConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(config, []byte("PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding no\n# this is a comment\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.sshdConfigPath = config

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var configObs *models.Observation
	for i := range obs {
		if obs[i].Kind == models.KindSSHDConfig {
			configObs = &obs[i]
			break
		}
	}
	if configObs == nil {
		t.Fatal("expected system.sshd_config observation")
	}
	if value, _ := configObs.Attr(models.AttrSSHDirective + ".permitrootlogin"); value != "yes" {
		t.Fatalf("permitrootlogin = %q, want yes", value)
	}
	if value, _ := configObs.Attr(models.AttrSSHDirective + ".passwordauthentication"); value != "yes" {
		t.Fatalf("passwordauthentication = %q, want yes", value)
	}
	if value, _ := configObs.Attr(models.AttrSSHDirective + ".x11forwarding"); value != "no" {
		t.Fatalf("x11forwarding = %q, want no", value)
	}
}

func TestSSHDCollectorMissingConfig(t *testing.T) {
	c := NewCollector()
	c.sshdConfigPath = filepath.Join(t.TempDir(), "sshd_config")

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindSSHDConfig {
			found = true
		}
	}
	if found {
		t.Fatal("expected no system.sshd_config observation for missing config")
	}
}

func TestSSHDCollectorAuthorizedKeysWritable(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "user")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0755); err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(ak, []byte("ssh-rsa AAAA...\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ak, 0664); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("user:x:1001:1001:user:"+home+":/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.sshdConfigPath = filepath.Join(t.TempDir(), "no-such-config")
	c.SetPasswdPath(passwd)

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindSSHAuthorizedKeys && o.Resource == ak {
			found = true
			if writable, _ := o.Attr(models.AttrAuthKeysWritable); writable != "true" {
				t.Fatalf("auth_keys_writable = %q, want true", writable)
			}
		}
	}
	if !found {
		t.Fatal("expected identity.ssh_authorized_keys observation for writable file")
	}
}

func TestSSHDCollectorAuthorizedKeysNotWritable(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "user")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0755); err != nil {
		t.Fatal(err)
	}
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(ak, []byte("ssh-rsa AAAA...\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ak, 0600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("user:x:1001:1001:user:"+home+":/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.sshdConfigPath = filepath.Join(t.TempDir(), "no-such-config")
	c.SetPasswdPath(passwd)

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, o := range obs {
		if o.Kind == models.KindSSHAuthorizedKeys && o.Resource == ak {
			found = true
			if writable, _ := o.Attr(models.AttrAuthKeysWritable); writable == "true" {
				t.Fatalf("auth_keys_writable = %q, want false for 0600", writable)
			}
		}
	}
	if !found {
		t.Fatal("expected identity.ssh_authorized_keys observation for non-writable file")
	}
}

func TestSSHDCollectorNoAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("user:x:1001:1001:user:/home/user:/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	c.sshdConfigPath = filepath.Join(t.TempDir(), "no-such-config")
	c.SetPasswdPath(passwd)

	obs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, o := range obs {
		if o.Kind == models.KindSSHAuthorizedKeys {
			t.Fatal("expected no identity.ssh_authorized_keys observation when file absent")
		}
	}
}
