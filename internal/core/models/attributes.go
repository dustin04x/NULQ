package models

// Attribute keys used by normalized observations.
//
// Attributes are stored as canonical strings so evidence values are stable,
// comparable and safe to serialise. Encoding conventions:
//
//   - booleans: "true" or "false"
//   - permissions: four octal digits, for example "4755"
//   - identifiers: unsigned decimal
//   - timestamps: RFC 3339 UTC
//   - lists: comma-separated, already sorted where order is meaningless
//
// Rules must not parse vendor-specific formats out of attributes; collectors
// own normalisation.
const (
	AttrMode                  = "mode"
	AttrModeSymbolic          = "mode_symbolic"
	AttrSetUID                = "setuid"
	AttrSetGID                = "setgid"
	AttrSticky                = "sticky"
	AttrWorldWritable         = "world_writable"
	AttrGroupWritable         = "group_writable"
	AttrWritableByCurrentUser = "writable_by_current_user"

	AttrOwnerUID  = "owner_uid"
	AttrOwnerUser = "owner_user"
	AttrGroupGID  = "group_gid"
	AttrGroupName = "group_name"
	AttrSizeBytes = "size_bytes"

	AttrPathIndex     = "path_index"
	AttrPathEntry     = "path_entry"
	AttrPathExists    = "path_exists"
	AttrIsDirectory   = "is_directory"
	AttrSymlink       = "symlink"
	AttrSymlinkTarget = "symlink_target"

	AttrUID          = "uid"
	AttrEUID         = "euid"
	AttrGID          = "gid"
	AttrEGID         = "egid"
	AttrUsername     = "username"
	AttrPrimaryGroup = "primary_group"
	AttrGroups       = "groups"
	AttrUmask        = "umask"

	AttrNamespaceMount  = "ns_mount"
	AttrNamespacePID    = "ns_pid"
	AttrNamespaceNet    = "ns_net"
	AttrNamespaceUser   = "ns_user"
	AttrNamespaceIPC    = "ns_ipc"
	AttrNamespaceUTS    = "ns_uts"
	AttrNamespaceCgroup = "ns_cgroup"

	AttrHostname         = "hostname"
	AttrKernelRelease    = "kernel_release"
	AttrKernelVersion    = "kernel_version"
	AttrArchitecture     = "architecture"
	AttrOSID             = "os_id"
	AttrOSName           = "os_name"
	AttrOSVersion        = "os_version"
	AttrContainer        = "container"
	AttrContainerRuntime = "container_runtime"
	AttrCgroupVersion    = "cgroup_version"
	AttrLSMList          = "lsm_list"

	AttrActive = "active"
	AttrDetail = "detail"
	AttrValue  = "value"
	AttrSource = "source"

	AttrFSType          = "fstype"
	AttrDevice          = "device"
	AttrMountPoint      = "mount_point"
	AttrMountOptions    = "mount_options"
	AttrReadOnly        = "read_only"
	AttrAssessed        = "assessed"
	AttrExclusionReason = "exclusion_reason"

	AttrScanRoots    = "scan_roots"
	AttrFilesVisited = "files_visited"
	AttrDirsVisited  = "dirs_visited"
	AttrScanErrors   = "scan_errors"
	AttrScanDenied   = "scan_denied"
	AttrTruncated    = "truncated"
)

// Process metadata. Only numeric identity, lifecycle and executable-path
// context is collected; environments, command lines, memory, descriptors and
// maps are never read.
const (
	AttrPID              = "pid"
	AttrPPID             = "ppid"
	AttrProcessName      = "comm"
	AttrProcessUID       = "process_uid"
	AttrProcessEUID      = "process_euid"
	AttrProcessGID       = "process_gid"
	AttrProcessEGID      = "process_egid"
	AttrProcessGroups    = "process_groups"
	AttrProcessStartTime = "start_time"
	AttrKernelThread     = "kernel_thread"
	AttrExePath          = "exe_path"
	AttrExeDeleted       = "exe_deleted"
	AttrExeReadable      = "exe_readable"
	AttrExeUID           = "exe_uid"
	AttrExeGID           = "exe_gid"
	AttrExeMode          = "exe_mode"
	AttrExeRegular       = "exe_regular"
	AttrExeSetUID        = "exe_setuid"
	AttrExeSetGID        = "exe_setgid"
	AttrExeMountPoint    = "exe_mount_point"
	AttrExeNosuid        = "exe_nosuid"
	AttrExeNoexec        = "exe_noexec"

	AttrParentPath           = "parent_path"
	AttrParentUID            = "parent_uid"
	AttrParentMode           = "parent_mode"
	AttrParentSticky         = "parent_sticky"
	AttrParentWorldWritable  = "parent_world_writable"
	AttrParentEffectiveWrite = "parent_effective_write"
	AttrParentEffectiveExec  = "parent_effective_exec"
	AttrParentACLStatus      = "parent_acl_status"
	AttrParentACLAccess      = "parent_acl_access"

	// Mount context of the parent directory. It is kept separate from the
	// executable's mount attributes because a bind-mounted single file can sit
	// on a different mount than the directory that contains it.
	AttrParentMountPoint = "parent_mount_point"
	AttrParentNosuid     = "parent_nosuid"
	AttrParentNoexec     = "parent_noexec"
)

// POSIX ACL and effective-permission metadata. ACL bytes are parsed by NULQ
// and normalized to text; raw xattrs are never stored in reports.
const (
	AttrACLStatus        = "acl_status"
	AttrACLAccess        = "acl_access"
	AttrACLMask          = "acl_mask"
	AttrACLDefaultStatus = "acl_default_status"
	AttrEffectiveWrite   = "effective_write"
	AttrEffectiveExec    = "effective_exec"
)

// Mount context attached to files, directories and process executable paths.
const (
	AttrMountID       = "mount_id"
	AttrParentMountID = "parent_mount_id"
	AttrMajorMinor    = "major_minor"
	AttrMountRoot     = "mount_root"
	AttrMountSource   = "mount_source"
	AttrSuperOptions  = "super_options"
	AttrMountOptional = "mount_optional"
	AttrNosuid        = "nosuid"
	AttrNodev         = "nodev"
	AttrNoexec        = "noexec"
)

// Process capability and seccomp metadata, read from /proc/<pid>/status.
// Capability values are hex strings as exposed by the kernel.
const (
	AttrCapEffective = "cap_effective"
	AttrCapBounding  = "cap_bounding"
	AttrSeccomp      = "seccomp"
)

// Systemd unit security directives, read from unit files.
const (
	AttrSystemdUser                  = "systemd_user"
	AttrSystemdNoNewPrivileges       = "systemd_no_new_privileges"
	AttrSystemdProtectSystem         = "systemd_protect_system"
	AttrSystemdProtectHome           = "systemd_protect_home"
	AttrSystemdPrivateTmp            = "systemd_private_tmp"
	AttrSystemdCapabilityBoundingSet = "systemd_capability_bounding_set"
)

// Resource kinds identify what a finding is about. They are a small closed
// vocabulary so downstream consumers and the relationship graph can reason
// about findings without parsing free-form paths.
const (
	ResourceFile            = "file"
	ResourceDirectory       = "directory"
	ResourcePathEntry       = "path_entry"
	ResourceUser            = "user"
	ResourceGroup           = "group"
	ResourceSysctl          = "sysctl"
	ResourceSecurityControl = "security_control"
	ResourceSystem          = "system"
	ResourceFilesystem      = "filesystem"
	ResourceProcess         = "process"
)
