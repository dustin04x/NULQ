# Test fixtures

NULQ does not commit executable fixtures or privileged trees. All fixtures are
created at test time in temporary directories, which keeps the repository free
of set-owner-ID binaries and makes the tests reproducible on any Linux runner
without root.

## Conventions

Set-owner-ID files:

```go
os.WriteFile(path, []byte("fixture"), 0o600)
os.Chmod(path, 0o755|fs.ModeSetuid)
```

`fs.ModeSetuid` is the Go `FileMode` bit. Passing `0o4755` sets only the
permission bits; the setuid bit is silently dropped, which caused an early test
suite to pass against non-SUID fixtures.

Directories:

```go
os.MkdirAll(dir, 0o755)
os.Chmod(dir, 0o777) // after creation, so umask cannot mask the bits
```

PATH isolation:

- library tests pass `app.ScanConfig.PathEnv`;
- CLI tests clear `PATH` with `t.Setenv("PATH", "")` and use `--root`;
- a PATH entry that is a symlink must resolve to a directory with the intended
  permissions, because the link's own mode is always `0777`.

## What is not here

- Root-owned files: cannot be created unprivileged. Rule tests synthesise
  observations for those cases.
- Snapshot or container mounts: excluded by default; scenarios cover the
  filtering logic instead of mounting filesystems.
- Kernel knob fixtures: units build observations directly; the live collector
  test tolerates missing knobs on the runner.
