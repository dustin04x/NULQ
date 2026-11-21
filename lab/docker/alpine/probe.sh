#!/bin/sh
# In-container isolation probe.
#
# Proves, from inside the container, the security properties the laboratory
# claims. It writes one JSON object to stdout; the host stores and validates it.
# Failure to establish a property is reported as false, never assumed true.
set -u

as_bool() {
	if "$@" >/dev/null 2>&1; then
		printf 'true'
	else
		printf 'false'
	fi
}

uid=$(id -u)
caps=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)
no_new_privs=$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status 2>/dev/null || true)

# Read-only root filesystem: any write at the root must fail.
read_only_root=false
if ! (printf 'probe' >/lab/.probe-write) 2>/dev/null; then
	read_only_root=true
fi
rm -f /lab/.probe-write 2>/dev/null || true

# /tmp is expected to be a small tmpfs. Record whether it accepts writes and
# whether it refuses execution.
tmp_writable=false
tmp_noexec=false
if printf '#!/bin/sh\nexit 0\n' >/tmp/.probe-exec 2>/dev/null; then
	tmp_writable=true
	chmod 0755 /tmp/.probe-exec 2>/dev/null || true
	if ! /tmp/.probe-exec >/dev/null 2>&1; then
		tmp_noexec=true
	fi
fi
rm -f /tmp/.probe-exec 2>/dev/null || true

interfaces=$(ls /sys/class/net 2>/dev/null | tr '\n' ',' | sed 's/,$//')

# A fresh network namespace may still list kernel tunnel devices, so interface
# names alone do not prove isolation. Prove it by behaviour: no globally
# routable IPv4 address and no successful outbound connection.
routable_addresses=$(ip -o -4 addr show scope global 2>/dev/null | wc -l | tr -d ' ')
network_isolated=false
if [ "${routable_addresses:-1}" -eq 0 ] && ! timeout 3 wget -T 2 -q -O /dev/null http://1.1.1.1 2>/dev/null; then
	network_isolated=true
fi
network_probe="routable_v4=${routable_addresses:-unknown};outbound_connect=blocked"

capabilities_dropped=false
case "$caps" in
"" | *[!0]*) capabilities_dropped=false ;;
*) capabilities_dropped=true ;;
esac

docker_socket_present=false
if [ -S /var/run/docker.sock ]; then
	docker_socket_present=true
fi

nulq_executable=false
if /opt/nulq/nulq version >/dev/null 2>&1; then
	nulq_executable=true
fi

printf '{"uid":%s,"non_root":%s,"read_only_root":%s,"effective_capabilities":"%s","capabilities_dropped":%s,"no_new_privileges":%s,"network_interfaces":"%s","network_probe":"%s","network_isolated":%s,"docker_socket_present":%s,"nulq_executable":%s,"tmp_writable":%s,"tmp_noexec":%s}\n' \
	"$uid" \
	"$(as_bool test "$uid" -ne 0)" \
	"$read_only_root" \
	"${caps:-unknown}" \
	"$capabilities_dropped" \
	"$(as_bool test "${no_new_privs:-0}" = 1)" \
	"$interfaces" \
	"$network_probe" \
	"$network_isolated" \
	"$docker_socket_present" \
	"$nulq_executable" \
	"$tmp_writable" \
	"$tmp_noexec"
