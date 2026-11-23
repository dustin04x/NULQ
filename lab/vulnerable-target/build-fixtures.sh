#!/bin/sh
# Build-time fixture construction for the NULQ vulnerable-target image.
#
# Runs as root inside the image build only. Every path here is inside the
# disposable image; nothing on the Docker host is touched.
#
# Fixtures express permission and ownership relationships relevant to NULQ's
# collectors, not a real distribution's package state. All binaries are inert
# copies of /bin/busybox: NULQ never executes them.
set -eu

FIX=/lab/fixtures
VT_UID=10001
VT_GID=10001
WHEEL_GID=10
OTHER_UID=10002
OTHER_GID=10002

install -d -m 0755 "$FIX"
for dir in \
	fs/clean \
	fs/world-writable \
	fs/world-writable-sticky \
	fs/group-writable \
	fs/world-writable-exec \
	fs/group-writable-exec \
	fs/writable-parent \
	fs/writable-parent/child \
	fs/ancestry \
	fs/ancestry/middle \
	fs/ancestry/middle/leaf \
	suid \
	sgid \
	path \
	path/writable \
	path/safe \
	path/late-writable \
	path/other-owned \
	path/relative \
	links \
	app \
	app/config \
	app/config/writable \
	app/bin \
	permissions \
	permissions/denied \
	identity \
	identity/wheel \
	mount
do
	install -d -m 0755 "$FIX/$dir"
done

# ---------------------------------------------------------------------------
# A. Filesystem permissions
# ---------------------------------------------------------------------------

# World-writable directory, no sticky bit: NULQ-FS-002 MEDIUM.
install -d -m 0777 "$FIX/fs/world-writable"

# World-writable directory with sticky bit: deletion restricted, no escalation.
install -d -m 1777 "$FIX/fs/world-writable-sticky"

# Group-writable only (root:wheel): not world-writable, no FS-002 finding.
install -d -m 0770 "$FIX/fs/group-writable"
chown "0:$WHEEL_GID" "$FIX/fs/group-writable"

# World-writable directory containing an executable file.
install -d -m 0777 "$FIX/fs/world-writable-exec"
cp /bin/busybox "$FIX/fs/world-writable-exec/tool"
chown 0:0 "$FIX/fs/world-writable-exec/tool"
chmod 0755 "$FIX/fs/world-writable-exec/tool"

# Group-writable executable file.
install -d -m 0777 "$FIX/fs/group-writable-exec"
cp /bin/busybox "$FIX/fs/group-writable-exec/tool"
chown "0:$WHEEL_GID" "$FIX/fs/group-writable-exec/tool"
chmod 0750 "$FIX/fs/group-writable-exec/tool"

# Writable parent directory with an unprivileged child.
install -d -m 0777 "$FIX/fs/writable-parent"
cp /bin/busybox "$FIX/fs/writable-parent/child/tool"
chown 0:0 "$FIX/fs/writable-parent/child/tool"
chmod 0755 "$FIX/fs/writable-parent/child/tool"

# Unsafe directory ancestry: deep leaf under writable middle under writable parent.
install -d -m 0777 "$FIX/fs/ancestry/middle"
install -d -m 0777 "$FIX/fs/ancestry/middle/leaf"
cp /bin/busybox "$FIX/fs/ancestry/middle/leaf/tool"
chown 0:0 "$FIX/fs/ancestry/middle/leaf/tool"
chmod 0755 "$FIX/fs/ancestry/middle/leaf/tool"

# Sticky-bit edge case: user-owned 1777 directory holding root SUID binary.
install -d -m 1777 "$FIX/fs/sticky-owned"
chown "$VT_UID:$VT_GID" "$FIX/fs/sticky-owned"
chmod 1777 "$FIX/fs/sticky-owned"
cp /bin/busybox "$FIX/fs/sticky-owned/tool"
chown 0:0 "$FIX/fs/sticky-owned/tool"
chmod 4755 "$FIX/fs/sticky-owned/tool"

# Negative control: ordinary directory and ordinary file.
install -d -m 0755 "$FIX/fs/clean"
printf 'plain fixture file\n' >"$FIX/fs/clean/plain.txt"
chmod 0644 "$FIX/fs/clean/plain.txt"
chown 0:0 "$FIX/fs/clean/plain.txt"

# ---------------------------------------------------------------------------
# B. SUID and SGID inventory
# ---------------------------------------------------------------------------

# Root-owned SUID executable: inventory (INFO in standard location).
cp /bin/busybox "$FIX/suid/root-owned-tool"
chown 0:0 "$FIX/suid/root-owned-tool"
chmod 4755 "$FIX/suid/root-owned-tool"

# SGID executable with unsafe group permission configuration.
cp /bin/busybox "$FIX/sgid/sgid-tool"
chown "0:$WHEEL_GID" "$FIX/sgid/sgid-tool"
chmod 2755 "$FIX/sgid/sgid-tool"

# SUID file in a writable directory: directory is replaceable through FS-002.
install -d -m 0777 "$FIX/sgid/writable-dir"
cp /bin/busybox "$FIX/sgid/writable-dir/suid-tool"
chown 0:0 "$FIX/sgid/writable-dir/suid-tool"
chmod 4755 "$FIX/sgid/writable-dir/suid-tool"

# Inert metadata: set-user-ID bit without execute bit is ignored by kernel.
cp /bin/busybox "$FIX/suid/inert-suid"
chown 0:0 "$FIX/suid/inert-suid"
chmod 4644 "$FIX/suid/inert-suid"

# Negative control: no set-owner-ID bit.
cp /bin/busybox "$FIX/suid/plain-tool"
chown 0:0 "$FIX/suid/plain-tool"
chmod 0755 "$FIX/suid/plain-tool"

# ---------------------------------------------------------------------------
# C. PATH configuration
# ---------------------------------------------------------------------------

# Writable PATH directory: unsafe PATH entry.
install -d -m 0777 "$FIX/path/writable"
cp /bin/busybox "$FIX/path/writable/payload"
chown 0:0 "$FIX/path/writable/payload"
chmod 0755 "$FIX/path/writable/payload"

# Safe PATH directory.
install -d -m 0755 "$FIX/path/safe"
cp /bin/busybox "$FIX/path/safe/tool"
chown 0:0 "$FIX/path/safe/tool"
chmod 0755 "$FIX/path/safe/tool"

# Writable PATH entry after trusted system locations: contextual LOW.
install -d -m 0777 "$FIX/path/late-writable"

# Owned by a different unprivileged account: not writable by uid 10001.
install -d -m 0755 "$FIX/path/other-owned"
chown "$OTHER_UID:$OTHER_GID" "$FIX/path/other-owned"

# Relative PATH entry: represented as a symlink to a non-writable directory.
ln -s "$FIX/path/safe" "$FIX/links/path-link"

# ---------------------------------------------------------------------------
# D. Application and service configuration
# ---------------------------------------------------------------------------

# Application directory with misconfigured ownership.
install -d -m 0755 "$FIX/app"
cp /bin/busybox "$FIX/app/tool"
chown "$OTHER_UID:$OTHER_GID" "$FIX/app/tool"
chmod 0755 "$FIX/app/tool"

# Writable configuration directory.
install -d -m 0777 "$FIX/app/config/writable"
printf 'synthetic config\n' >"$FIX/app/config/writable/settings.conf"
chown 0:0 "$FIX/app/config/writable/settings.conf"
chmod 0666 "$FIX/app/config/writable/settings.conf"

# Application bin directory with unsafe executable ownership.
install -d -m 0755 "$FIX/app/bin"
cp /bin/busybox "$FIX/app/bin/app-tool"
chown 0:0 "$FIX/app/bin/app-tool"
chmod 0755 "$FIX/app/bin/app-tool"

# Service-related configuration file with incorrect permissions.
printf '[Service]\nExecStart=/usr/bin/id\n' >"$FIX/app/config/service.conf"
chown 0:0 "$FIX/app/config/service.conf"
chmod 0644 "$FIX/app/config/service.conf"

# ---------------------------------------------------------------------------
# F. Identity and access control
# ---------------------------------------------------------------------------

# Wheel membership: non-root user with supplementary group relationship.
install -d -m 0755 "$FIX/identity/wheel"
cp /bin/busybox "$FIX/identity/wheel/group-tool"
chown "$VT_UID:$WHEEL_GID" "$FIX/identity/wheel/group-tool"
chmod 0750 "$FIX/identity/wheel/group-tool"

# ---------------------------------------------------------------------------
# Coverage honesty: unreadable subtree
# ---------------------------------------------------------------------------

install -d -m 0700 "$FIX/permissions/denied"
printf 'synthetic secret; never read by NULQ\n' >"$FIX/permissions/denied/secret.txt"
chmod 0600 "$FIX/permissions/denied/secret.txt"
chown 0:0 "$FIX/permissions/denied" "$FIX/permissions/denied/secret.txt"

# ---------------------------------------------------------------------------
# Final: fixture tree must stay traversable by the unprivileged account.
# ---------------------------------------------------------------------------

chmod 0755 "$FIX"
