#!/bin/sh
# Build-time fixture construction for the NULQ laboratory image.
#
# Runs as root inside the image build only. Every path here is inside the
# disposable image; nothing on the Docker host is touched. Fixtures are
# intentionally synthetic: they express permission and ownership relationships,
# not a real distribution's package state.
set -eu

FIX=/lab/fixtures
LAB_UID=10001
LAB_GID=10001
WHEEL_GID=10

install -d -m 0755 "$FIX"
for dir in \
	fs/clean \
	fs/world-writable-sticky \
	fs/group-writable \
	fs/nested/deep \
	fs/ww-with-suid \
	suid \
	path \
	links \
	permissions \
	capabilities \
	sudo/sudoers.d \
	systemd \
	cron \
	containers
do
	install -d -m 0755 "$FIX/$dir"
done

# ---------------------------------------------------------------------------
# Filesystem permissions
# ---------------------------------------------------------------------------

# Writable by everyone, no sticky bit: NULQ-FS-002 MEDIUM.
install -d -m 0777 "$FIX/fs/world-writable"

# Writable by everyone but sticky: deletion stays restricted, no finding.
install -d -m 1777 "$FIX/fs/world-writable-sticky"

# Group-writable only (root:wheel): not world-writable, no finding.
install -d -m 0770 "$FIX/fs/group-writable"
chown "0:$WHEEL_GID" "$FIX/fs/group-writable"

# Nested case: the finding must be attributed to the inner directory.
install -d -m 0777 "$FIX/fs/nested/deep/world-writable"

# World-writable directory containing a privileged executable: FS-002
# escalates to HIGH because a name in this directory can be replaced.
install -d -m 0777 "$FIX/fs/ww-with-suid"
cp /bin/busybox "$FIX/fs/ww-with-suid/tool"
# chown clears the set-user-ID/set-group-ID bits on regular files, so
# ownership must always be set before the privileged mode bits.
chown 0:0 "$FIX/fs/ww-with-suid/tool"
chmod 4755 "$FIX/fs/ww-with-suid/tool"

# Negative control: a privileged executable inside a subdirectory is not
# directly replaceable through the writable parent. FS-002 must stay MEDIUM.
install -d -m 0777 "$FIX/fs/ww-nested-suid"
install -d -m 0755 "$FIX/fs/ww-nested-suid/inner"
cp /bin/busybox "$FIX/fs/ww-nested-suid/inner/tool"
chown 0:0 "$FIX/fs/ww-nested-suid/inner/tool"
chmod 4755 "$FIX/fs/ww-nested-suid/inner/tool"

# Negative control: a user-owned SUID executable is replaceable but grants
# only that user's authority, so the directory stays MEDIUM.
install -d -m 0777 "$FIX/fs/ww-with-user-suid"
cp /bin/busybox "$FIX/fs/ww-with-user-suid/tool"
chown "$LAB_UID:$LAB_GID" "$FIX/fs/ww-with-user-suid/tool"
chmod 4755 "$FIX/fs/ww-with-user-suid/tool"

# Sticky bit does not protect entries from the directory's owner. A user-owned
# 1777 directory holding a root SUID binary is replaceable by that user.
install -d -m 1777 "$FIX/fs/sticky-owned"
chown "$LAB_UID:$LAB_GID" "$FIX/fs/sticky-owned"
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
# SUID / SGID inventory
# ---------------------------------------------------------------------------

# Real ELF copies of busybox: metadata is realistic, and NULQ never executes
# them. A SUID bit on a shell script would be ignored by the kernel and would
# make the fixture misleading.
cp /bin/busybox "$FIX/suid/root-owned-tool"
chown 0:0 "$FIX/suid/root-owned-tool"
chmod 4755 "$FIX/suid/root-owned-tool"

cp /bin/busybox "$FIX/suid/sgid-tool"
chown "0:$WHEEL_GID" "$FIX/suid/sgid-tool"
chmod 2755 "$FIX/suid/sgid-tool"

# Owned by the assessment account: delegated authority, never root authority.
cp /bin/busybox "$FIX/suid/user-owned-tool"
chown "$LAB_UID:$LAB_GID" "$FIX/suid/user-owned-tool"
chmod 4755 "$FIX/suid/user-owned-tool"

# Inert metadata: the set-user-ID bit without any execute bit is ignored by
# the kernel and must be INFO, never HIGH.
cp /bin/busybox "$FIX/suid/inert-suid"
chown 0:0 "$FIX/suid/inert-suid"
chmod 4644 "$FIX/suid/inert-suid"

# Negative control: no set-owner-ID bit.
cp /bin/busybox "$FIX/suid/plain-tool"
chown 0:0 "$FIX/suid/plain-tool"
chmod 0755 "$FIX/suid/plain-tool"

# Distribution-style location: a privileged executable inside a standard
# binary directory is inventory (INFO), never escalated on presence alone.
install -d -m 0755 /usr/lib/lab
cp /bin/busybox /usr/lib/lab/standard-suid
chown 0:0 /usr/lib/lab/standard-suid
chmod 4755 /usr/lib/lab/standard-suid

# ---------------------------------------------------------------------------
# PATH fixtures
# ---------------------------------------------------------------------------

install -d -m 0777 "$FIX/path/writable"
install -d -m 0755 "$FIX/path/safe"
install -d -m 0755 "$FIX/path/user-owned"
chown "$LAB_UID:$LAB_GID" "$FIX/path/user-owned"

# Writable PATH entry that appears after trusted system locations. It is a
# contextual LOW (no privileged consumer observed), never HIGH.
install -d -m 0777 "$FIX/path/late-writable"

# Owned by a different unprivileged account and not writable by uid 10001:
# mode bits alone must not produce a PATH finding.
install -d -m 0755 "$FIX/path/other-owned"
chown 10002:10002 "$FIX/path/other-owned"

# A PATH entry that is a symlink to a non-writable directory: the resolved
# target decides permissions, so this must stay silent (regression guard).
ln -s "$FIX/path/safe" "$FIX/links/path-link"
ln -s "$FIX/fs/clean/plain.txt" "$FIX/links/safe-link"

# ---------------------------------------------------------------------------
# Unreadable subtree (coverage honesty)
# ---------------------------------------------------------------------------

install -d -m 0700 "$FIX/permissions/denied"
printf 'synthetic secret; never read by NULQ\n' >"$FIX/permissions/denied/secret.txt"
chmod 0600 "$FIX/permissions/denied/secret.txt"
chown 0:0 "$FIX/permissions/denied" "$FIX/permissions/denied/secret.txt"

# ---------------------------------------------------------------------------
# Synthetic fixtures for checks that are not implemented yet (M3).
# They are reported as unsupported scenarios, never as passing checks.
# ---------------------------------------------------------------------------

cp /bin/busybox "$FIX/capabilities/example.bin"
chmod 0755 "$FIX/capabilities/example.bin"
chown 0:0 "$FIX/capabilities/example.bin"
printf 'cap_net_raw+ep %s\n' "$FIX/capabilities/example.bin" \
	>"$FIX/capabilities/capability-set.txt"

printf 'labuser ALL=(root) NOPASSWD: /usr/bin/id\n' >"$FIX/sudo/sudoers.d/10-nopasswd"
printf 'this line is deliberately malformed {{{ not a sudoers rule\n' >"$FIX/sudo/sudoers.d/20-malformed"
printf 'labuser ALL=(root) /usr/bin/id\n' >"$FIX/sudo/sudoers.d/30-safe"
chmod 0750 "$FIX/sudo/sudoers.d"
chmod 0440 "$FIX/sudo/sudoers.d/"*
chown 0:0 "$FIX/sudo/sudoers.d" "$FIX/sudo/sudoers.d/"*

cat >"$FIX/systemd/lab.service" <<'EOF'
[Unit]
Description=NULQ synthetic privileged unit fixture

[Service]
Type=oneshot
User=root
ExecStart=/lab/fixtures/path/writable/payload
EOF
cat >"$FIX/systemd/lab.timer" <<'EOF'
[Unit]
Description=NULQ synthetic timer fixture

[Timer]
OnCalendar=daily
Unit=lab.service
EOF
chmod 0644 "$FIX/systemd/lab.service" "$FIX/systemd/lab.timer"
chown 0:0 "$FIX/systemd" "$FIX/systemd/lab.service" "$FIX/systemd/lab.timer"

printf '# synthetic cron fixture; never installed or executed\n* * * * * root /lab/fixtures/path/writable/payload\n' \
	>"$FIX/cron/root"
chmod 0600 "$FIX/cron/root"
chown 0:0 "$FIX/cron/root"

printf '#!/bin/sh\necho fixture payload\n' >"$FIX/path/writable/payload"
chmod 0755 "$FIX/path/writable/payload"
chown 0:0 "$FIX/path/writable/payload"

cat >"$FIX/containers/privileged.json" <<'EOF'
{
  "fixture": true,
  "privileged": true,
  "network_mode": "host",
  "cap_add": ["SYS_ADMIN"],
  "volumes": ["/:/host"]
}
EOF
chmod 0644 "$FIX/containers/privileged.json"
chown 0:0 "$FIX/containers" "$FIX/containers/privileged.json"

# The fixture tree itself must stay traversable by the unprivileged account.
chmod 0755 "$FIX"
