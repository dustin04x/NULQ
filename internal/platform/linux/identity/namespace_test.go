package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectProcessNamespaces(t *testing.T) {
	root := t.TempDir()
	// process 1 with ns
	p1 := filepath.Join(root, "1", "ns")
	os.MkdirAll(p1, 0755)
	os.Symlink("mnt:[4026531840]", filepath.Join(p1, "mnt"))
	// process 2 disappearing (no ns dir)
	os.MkdirAll(filepath.Join(root, "2"), 0755)
	res := CollectProcessNamespaces(root)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].PID != 1 {
		t.Fatalf("expected pid 1, got %d", res[0].PID)
	}
	if res[0].Links["mnt"] != "mnt:[4026531840]" {
		t.Fatalf("bad link: %s", res[0].Links["mnt"])
	}
}
