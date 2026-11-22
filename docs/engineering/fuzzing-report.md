# Fuzzing Report — NULQ

This report documents fuzzing coverage for NULQ's input parsers. Fuzzing
targets parsers that consume untrusted text from the assessed system.

## 1. Parser inventory

| Parser | Location | Input source | Fuzzed |
|--------|----------|--------------|--------|
| Mountinfo parser | `internal/platform/linux/filesystem/mounts.go` | /proc/self/mountinfo | No |
| Mounts parser | `internal/platform/linux/filesystem/mounts.go` | /proc/mounts | No |
| ACL parser | `internal/platform/linux/acl/acl.go` | xattr from filesystem | No |
| Systemd directive parser | `internal/platform/linux/systemd/collector.go` | .service unit files | No |
| Unit test parsers | Various rule test helpers | Synthetic observations | N/A |

## 2. Parser characteristics

### Mountinfo parser (`ParseMountInfo`)

- Input: bytes from /proc/self/mountinfo
- Format: 11+ space-separated fields per line, octal-escaped paths
- Validation: field count, numeric ID/major/minor, separator dash,
  filesystem type, source, superblock options
- Error handling: malformed lines are collected as parse errors; valid
  records are not discarded
- Fuzzing target: high value — mountinfo from an untrusted container or
  manipulated /proc could contain malformed records

### Mounts parser (`ReadMounts`)

- Input: bytes from /proc/mounts
- Format: 4+ space-separated fields per line
- Validation: field count >= 4
- Error handling: scanner errors returned
- Fuzzing target: medium value

### ACL parser

- Input: POSIX ACL text from xattr
- Format: ACL user/group/mask/other entries
- Error handling: parse errors classified
- Fuzzing target: high value — malformed ACL state could cause incorrect
  effective permission decisions

### Systemd directive parser (`parseUnitDirectives`)

- Input: .service unit file contents
- Format: key=value lines under [Service] section
- Validation: section tracking, key whitelist (6 directives)
- Error handling: unknown keys silently ignored
- Fuzzing target: medium value

## 3. Fuzzing gaps

| Parser | Risk | Priority | Plan |
|--------|------|----------|------|
| Mountinfo | High (mount data affects findings) | High | Add Go native fuzzing test |
| ACL | High (ACL affects effective permissions) | High | Add Go native fuzzing test |
| Systemd | Medium (unit files affect systemd findings) | Medium | Add Go native fuzzing test |
| Mounts | Medium (/proc/mounts parsing) | Medium | Add Go native fuzzing test |

## 4. Recommended fuzzing approach

Use Go 1.27 native fuzzing (`go test -fuzz=...`):

```go
func FuzzMountInfo(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        _, _, err := ParseMountInfo(data)
        _ = err
    })
}

func FuzzACL(f *testing.F) {
    f.Fuzz(func(t *testing.T, data []byte) {
        // Parse ACL text from data
    })
}
```

## 5. Current status

No fuzzing tests exist in the repository. This is a documented gap.
Fuzzing should be added before the next release, targeting the mountinfo
and ACL parsers as highest priority.
