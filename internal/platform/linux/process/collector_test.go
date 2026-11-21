//go:build linux

package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

func writeStatus(t *testing.T, proc, pid, name string, uid, euid, gid, egid uint32, kthread bool) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "Name:\t" + name + "\n" +
		"State:\tS (sleeping)\n" +
		"PPid:\t1\n" +
		"Uid:\t" + strconv.FormatUint(uint64(uid), 10) + "\t" + strconv.FormatUint(uint64(euid), 10) + "\t" + strconv.FormatUint(uint64(euid), 10) + "\t" + strconv.FormatUint(uint64(euid), 10) + "\n" +
		"Gid:\t" + strconv.FormatUint(uint64(gid), 10) + "\t" + strconv.FormatUint(uint64(egid), 10) + "\t" + strconv.FormatUint(uint64(egid), 10) + "\t" + strconv.FormatUint(uint64(egid), 10) + "\n" +
		"Groups:\t" + strconv.FormatUint(uint64(egid), 10) + "\n"
	if kthread {
		body += "Kthread:\t1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeStat(t *testing.T, proc, pid string, start string) {
	t.Helper()
	dir := filepath.Join(proc, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Field 22 is starttime. The first 19 fields after comm are placeholders.
	rest := []string{"S", "1", "1", "1", "0", "-1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "20", "0", "1", "0", start}
	line := pid + " (fixture process) " + strings.Join(rest, " ") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

func collectorFor(proc string, max int) *Collector {
	return NewCollector(Options{ProcRoot: proc, MountInfoPath: filepath.Join(proc, "missing-mountinfo"), MaxProcesses: max}, nil)
}

func TestCurrentProcessIsObserved(t *testing.T) {
	collector := NewCollector(Options{ProcRoot: "/proc", MountInfoPath: "/proc/self/mountinfo"}, nil)
	observations, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect current process: %v", err)
	}
	pid := strconv.Itoa(os.Getpid())
	for _, obs := range observations {
		if obs.Kind == models.KindProcess && obs.Resource == "/proc/"+pid {
			if obs.Status != models.StatusComplete && obs.Status != models.StatusPartial {
				t.Fatalf("current process status = %s", obs.Status)
			}
			if value, _ := obs.Attr(models.AttrProcessEUID); value == "" {
				t.Fatal("current process has no effective UID")
			}
			return
		}
	}
	t.Fatalf("current process %s was not observed", pid)
}

func TestSyntheticProcessAndWritableParentContext(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	parent := filepath.Join(root, "writable")
	if err := os.MkdirAll(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(parent, "tool")
	if err := os.WriteFile(exe, []byte("not executed"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeStatus(t, proc, "123", "fixture", 0, 0, 0, 0, false)
	writeStat(t, proc, "123", "1000")
	if err := os.Symlink(exe, filepath.Join(proc, "123", "exe")); err != nil {
		t.Fatal(err)
	}
	observations, err := collectorFor(proc, 10).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect synthetic process: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(observations))
	}
	obs := observations[0]
	if obs.Status != models.StatusComplete {
		t.Fatalf("status = %s, error = %+v", obs.Status, obs.Error)
	}
	if value, _ := obs.Attr(models.AttrExePath); value != exe {
		t.Fatalf("exe_path = %q, want %q", value, exe)
	}
	if value, _ := obs.Attr(models.AttrParentPath); value != parent {
		t.Fatalf("parent_path = %q, want %q", value, parent)
	}
	if value, _ := obs.Attr(models.AttrParentWorldWritable); value != "true" {
		t.Fatalf("parent_world_writable = %q", value)
	}
	if value, _ := obs.Attr(models.AttrParentEffectiveWrite); value == "" {
		t.Fatal("effective parent write was not evaluated")
	}
	if value, _ := obs.Attr(models.AttrExeSetUID); value != "false" {
		t.Fatalf("exe_setuid = %q", value)
	}
}

func TestDeletedExecutableRepresentation(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	writeStatus(t, proc, "55", "deleted", 1000, 1000, 1000, 1000, false)
	writeStat(t, proc, "55", "2000")
	if err := os.Symlink("/tmp/does-not-exist (deleted)", filepath.Join(proc, "55", "exe")); err != nil {
		t.Fatal(err)
	}
	observations, err := collectorFor(proc, 10).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	obs := observations[0]
	if value, _ := obs.Attr(models.AttrExeDeleted); value != "true" {
		t.Fatalf("exe_deleted = %q", value)
	}
	if value, _ := obs.Attr(models.AttrExePath); strings.HasSuffix(value, " (deleted)") {
		t.Fatalf("deleted marker was not removed from %q", value)
	}
}

func TestKernelThreadHasNoExecutable(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	writeStatus(t, proc, "2", "kthreadd", 0, 0, 0, 0, true)
	writeStat(t, proc, "2", "3000")
	observations, err := collectorFor(proc, 10).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	obs := observations[0]
	if obs.Status != models.StatusComplete {
		t.Fatalf("kernel thread status = %s", obs.Status)
	}
	if value, _ := obs.Attr(models.AttrKernelThread); value != "true" {
		t.Fatalf("kernel_thread = %q", value)
	}
	if _, ok := obs.Attr(models.AttrExePath); ok {
		t.Fatal("kernel thread must not invent an executable path")
	}
}

func TestMalformedStatusBecomesExplicitUnavailable(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	dir := filepath.Join(proc, "77")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStat(t, proc, "77", "4000")
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tbroken\nPPid:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	observations, err := collectorFor(proc, 10).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	if observations[0].Status != models.StatusUnavailable || observations[0].Error.Class != string(nulqerr.ClassMalformedInput) {
		t.Fatalf("unexpected observation: %+v", observations[0])
	}
}

func TestPermissionDeniedStatusIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses synthetic file permissions")
	}
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	writeStatus(t, proc, "88", "denied", 1, 1, 1, 1, false)
	writeStat(t, proc, "88", "5000")
	statusPath := filepath.Join(proc, "88", "status")
	if err := os.Chmod(statusPath, 0); err != nil {
		t.Fatal(err)
	}
	observations, err := collectorFor(proc, 10).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	if observations[0].Status != models.StatusUnavailable || observations[0].Error.Class != string(nulqerr.ClassPermissionDenied) {
		t.Fatalf("unexpected observation: %+v", observations[0])
	}
}

func TestPIDReuseDiscardsAttributes(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	writeStatus(t, proc, "99", "reused", 1000, 1000, 1000, 1000, false)
	writeStat(t, proc, "99", "6000")
	collector := collectorFor(proc, 10)
	calls := 0
	collector.readStart = func(string) (string, error) {
		calls++
		if calls == 1 {
			return "6000", nil
		}
		return "6001", nil
	}
	observations, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	obs := observations[0]
	if obs.Status != models.StatusPartial || obs.Error.Class != string(nulqerr.ClassNotFound) {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if _, ok := obs.Attr(models.AttrExePath); ok {
		t.Fatal("attributes from a reused PID were published")
	}
}

func TestProcessBudgetIsBounded(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	for _, pid := range []string{"10", "11"} {
		writeStatus(t, proc, pid, "fixture", 1000, 1000, 1000, 1000, false)
		writeStat(t, proc, pid, "7000")
	}
	observations, err := collectorFor(proc, 1).Collect(context.Background())
	if err == nil || !nulqerr.IsClass(err, nulqerr.ClassResourceExhausted) {
		t.Fatalf("error = %v, want resource_exhausted", err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations before budget stop, want 1", len(observations))
	}
}

func TestCancellationStopsCollection(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	writeStatus(t, proc, "12", "fixture", 1000, 1000, 1000, 1000, false)
	writeStat(t, proc, "12", "8000")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collectorFor(proc, 10).Collect(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestUnreadableProcRootIsExplicit(t *testing.T) {
	_, err := collectorFor(filepath.Join(t.TempDir(), "missing"), 10).Collect(context.Background())
	if err == nil || !nulqerr.IsClass(err, nulqerr.ClassNotFound) {
		t.Fatalf("error = %v, want not_found", err)
	}
}

func TestProcessPublishesParentExecAndSeparateMountContext(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	parent := filepath.Join(root, "bin")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(parent, "tool")
	if err := os.WriteFile(exe, []byte("not executed"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeStatus(t, proc, "321", "fixture", 1000, 1000, 1000, 1000, false)
	writeStat(t, proc, "321", "5000")
	if err := os.Symlink(exe, filepath.Join(proc, "321", "exe")); err != nil {
		t.Fatal(err)
	}
	// The executable is a bind mount without noexec; its directory sits on a
	// different mount with nosuid. The two contexts must not be conflated.
	mountinfo := filepath.Join(root, "mountinfo")
	body := "100 1 0:50 / " + exe + " rw,noexec - ext4 /dev/sdb rw\n" +
		"101 1 0:51 / " + parent + " rw,nosuid - ext4 /dev/sdc rw\n"
	if err := os.WriteFile(mountinfo, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewCollector(Options{ProcRoot: proc, MountInfoPath: mountinfo, MaxProcesses: 10}, nil)
	observations, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations", len(observations))
	}
	obs := observations[0]
	expect := func(key, want string) {
		t.Helper()
		if value, _ := obs.Attr(key); value != want {
			t.Fatalf("%s = %q, want %q", key, value, want)
		}
	}
	for _, key := range []string{models.AttrParentEffectiveWrite, models.AttrParentEffectiveExec} {
		if value, _ := obs.Attr(key); value == "" {
			t.Fatalf("%s was not evaluated", key)
		}
	}
	expect(models.AttrParentMountPoint, parent)
	expect(models.AttrParentNosuid, "true")
	expect(models.AttrParentNoexec, "false")
	expect(models.AttrExeMountPoint, exe)
	expect(models.AttrExeNosuid, "false")
	expect(models.AttrExeNoexec, "true")
}
