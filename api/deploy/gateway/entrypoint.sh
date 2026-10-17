#!/bin/sh
# OpenCTEM gateway entrypoint: check the settings, export the internal CA's
# root certificate for sensors (TLS mode `internal`), then run Caddy.
#
# Portable: the same Caddyfile and script serve the Compose `gateway` service
# and an image that runs the API, the web UI and Caddy together. Paths and
# upstreams come from the environment:
#   OPENCTEM_GATEWAY_DIR    Caddyfile + modes/          (default /etc/caddy)
#   OPENCTEM_CA_EXPORT_DIR  where the root CA is copied (default /ca; skipped
#                           when the directory does not exist)
#   OPENCTEM_CERT_DIR       TLS mode files: cert + key  (default /certs)
#   XDG_DATA_HOME           Caddy's storage             (default /data)
#   OPENCTEM_API_UPSTREAM   API address                 (Caddyfile default api:8080)
#   OPENCTEM_WEB_UPSTREAM   web UI address              (Caddyfile default web:3000)
# Arguments, when given, replace the final `caddy run` (e.g. a process
# supervisor that starts Caddy itself); the checks and CA export still run.
set -eu

gateway_dir="${OPENCTEM_GATEWAY_DIR:-/etc/caddy}"
ca_dir="${OPENCTEM_CA_EXPORT_DIR:-/ca}"
data_dir="${XDG_DATA_HOME:-/data}"

die() {
	echo "openctem-gateway: $*" >&2
	exit 64
}

mode="${OPENCTEM_TLS_MODE:-}"
case "$mode" in
internal | acme | files | http) ;;
"") die "OPENCTEM_TLS_MODE is not set (internal | acme | files | http)" ;;
*) die "OPENCTEM_TLS_MODE=$mode is not one of: internal, acme, files, http" ;;
esac

if [ "$mode" != http ] && [ -z "${OPENCTEM_HOSTNAME:-}" ]; then
	die "OPENCTEM_HOSTNAME is not set (the DNS name or IP address clients use)"
fi

case "$mode" in
acme)
	[ -n "${ACME_EMAIL:-}" ] || die "TLS mode acme needs ACME_EMAIL (Let's Encrypt account contact)"
	;;
files)
	cert_dir="${OPENCTEM_CERT_DIR:-/certs}"
	cert="$cert_dir/${TLS_CERT_FILE:-tls.crt}"
	key="$cert_dir/${TLS_KEY_FILE:-tls.key}"
	[ -r "$cert" ] || die "TLS mode files: certificate $cert is missing or unreadable (mount your certificate directory at $cert_dir)"
	[ -r "$key" ] || die "TLS mode files: private key $key is missing or unreadable"
	;;
http)
	if [ "${OPENCTEM_ALLOW_PLAIN_HTTP:-}" != "true" ]; then
		die "TLS mode http serves OpenCTEM WITHOUT encryption. Use it only behind a proxy that terminates TLS, and confirm with OPENCTEM_ALLOW_PLAIN_HTTP=true"
	fi
	echo "openctem-gateway: WARNING: plain HTTP mode. Passwords, session cookies and sensor keys cross the network unencrypted unless a TLS proxy sits in front of this gateway." >&2
	if [ -z "${OPENCTEM_TRUSTED_PROXIES:-}" ]; then
		echo "openctem-gateway: WARNING: OPENCTEM_TRUSTED_PROXIES is not set, so the audit log will record the front proxy's address instead of the client's." >&2
	fi
	;;
esac

# Which header a trusted front proxy carries the client address in. Only
# headers a proxy sets for the client are accepted: a free-form name would let
# a typo (or a header the client controls end to end) decide the address.
# Empty means the default, as Caddy would otherwise read an empty list.
client_ip_headers="${OPENCTEM_CLIENT_IP_HEADERS:-X-Forwarded-For}"
for h in $client_ip_headers; do
	case "$(printf '%s' "$h" | tr '[:upper:]' '[:lower:]')" in
	x-forwarded-for | cf-connecting-ip | true-client-ip) ;;
	*) die "OPENCTEM_CLIENT_IP_HEADERS: $h is not one of: X-Forwarded-For, Cf-Connecting-Ip, True-Client-Ip (space-separated, tried in order)" ;;
	esac
done
export OPENCTEM_CLIENT_IP_HEADERS="$client_ip_headers"
if [ "$client_ip_headers" != X-Forwarded-For ] && [ -z "${OPENCTEM_TRUSTED_PROXIES:-}" ]; then
	echo "openctem-gateway: WARNING: OPENCTEM_CLIENT_IP_HEADERS=$client_ip_headers has no effect without OPENCTEM_TRUSTED_PROXIES (the proxy that sets it)" >&2
fi

# Sensor protocol v3 gRPC binding (RFC-059 §5): layer-4 routing on this
# port to the API's mTLS listener, by the sensor ALPN id (alpn) or by the
# ALPN id and a dedicated sensor host name (passthrough).
need_layer4() {
	[ "$mode" != http ] || die "OPENCTEM_SENSOR_GATEWAY=$1 needs a TLS mode (the gateway must see the TLS ClientHello to route it)"
	caddy list-modules 2>/dev/null | grep -q '^layer4$' ||
		die "OPENCTEM_SENSOR_GATEWAY=$1 needs the gateway image with the layer4 module (deploy/gateway/Dockerfile, docker-compose.sensor-passthrough.yml)"
}
case "${OPENCTEM_SENSOR_GATEWAY:-off}" in
off) ;;
alpn)
	need_layer4 alpn
	[ -z "${SENSOR_PUBLIC_HOSTNAME:-}" ] ||
		echo "openctem-gateway: SENSOR_PUBLIC_HOSTNAME is ignored with OPENCTEM_SENSOR_GATEWAY=alpn; use passthrough to also route that host name" >&2
	;;
passthrough)
	sensor_host="${SENSOR_PUBLIC_HOSTNAME:-}"
	[ -n "$sensor_host" ] || die "OPENCTEM_SENSOR_GATEWAY=passthrough needs SENSOR_PUBLIC_HOSTNAME (the DNS name sensors dial for gRPC, without a port); for the ALPN routing alone use alpn"
	case "$sensor_host" in
	*:* | */* | *" "*) die "SENSOR_PUBLIC_HOSTNAME=$sensor_host must be a host name only (no port, path or space)" ;;
	esac
	[ "$sensor_host" != "${OPENCTEM_HOSTNAME:-}" ] || die "SENSOR_PUBLIC_HOSTNAME must differ from OPENCTEM_HOSTNAME: the gateway routes the sensor host by its name (SNI); for one host name use alpn"
	need_layer4 passthrough
	;;
*) die "OPENCTEM_SENSOR_GATEWAY=${OPENCTEM_SENSOR_GATEWAY} is not one of: off, alpn, passthrough" ;;
esac

# Platform console site (RFC-022 revision 20): off, port (a second port of
# the main host name) or host (its own host name). Private networks only by
# default (OPENCTEM_ADMIN_ALLOWED_CIDRS, space-separated).
admin_site="${OPENCTEM_ADMIN_SITE:-off}"
scheme=https
[ "$mode" != http ] || scheme=http
case "$admin_site" in
off) export OPENCTEM_ADMIN_SITE_FILE=off ;;
port)
	admin_port="${OPENCTEM_ADMIN_PORT:-8444}"
	case "$admin_port" in
	'' | *[!0-9]*) die "OPENCTEM_ADMIN_PORT=$admin_port is not a port number" ;;
	esac
	[ "$admin_port" != 443 ] && [ "$admin_port" != 80 ] || die "OPENCTEM_ADMIN_PORT must not be the main site's port"
	if [ "$mode" = http ]; then
		export OPENCTEM_ADMIN_ADDRESS="http://:$admin_port"
	else
		export OPENCTEM_ADMIN_ADDRESS="https://${OPENCTEM_HOSTNAME}:$admin_port"
	fi
	export OPENCTEM_ADMIN_SITE_FILE=on
	;;
host)
	admin_host="${OPENCTEM_ADMIN_HOST:-}"
	[ -n "$admin_host" ] || die "OPENCTEM_ADMIN_SITE=host needs OPENCTEM_ADMIN_HOST (the console's own DNS name, e.g. admin.example.com)"
	case "$admin_host" in
	*:* | */* | *" "*) die "OPENCTEM_ADMIN_HOST=$admin_host must be a host name only (no scheme, port, path or space)" ;;
	esac
	[ "$admin_host" != "${OPENCTEM_HOSTNAME:-}" ] || die "OPENCTEM_ADMIN_HOST must differ from OPENCTEM_HOSTNAME; for one host name use OPENCTEM_ADMIN_SITE=port"
	export OPENCTEM_ADMIN_ADDRESS="$scheme://$admin_host"
	export OPENCTEM_ADMIN_SITE_FILE=on
	;;
*) die "OPENCTEM_ADMIN_SITE=$admin_site is not one of: off, port, host" ;;
esac
if [ "$admin_site" != off ]; then
	cidrs="${OPENCTEM_ADMIN_ALLOWED_CIDRS:-127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7}"
	for c in $cidrs; do
		case "$c" in
		*[!0-9a-fA-F:./]* | "") die "OPENCTEM_ADMIN_ALLOWED_CIDRS: $c is not an IP address or CIDR (space-separated)" ;;
		esac
	done
	export OPENCTEM_ADMIN_ALLOWED_CIDRS="$cidrs"
	case " $cidrs " in
	*" 0.0.0.0/0 "*) echo "openctem-gateway: WARNING: the platform console is reachable from every network (OPENCTEM_ADMIN_ALLOWED_CIDRS)" >&2 ;;
	esac
fi

# A non-root gateway needs its data and config directories (certificates, the
# internal CA, the ACME account, the autosaved config) to be its own. Volumes
# written by an older gateway that ran as root hold root-owned files it cannot
# read: say how to fix that instead of failing later with a TLS error.
uid="$(id -u)"
if [ "$uid" != 0 ]; then
	for d in "$data_dir" "${XDG_CONFIG_HOME:-/config}"; do
		[ -d "$d" ] || continue
		other="$(find "$d" ! -user "$uid" -print 2>/dev/null | head -n 1)"
		if [ -n "$other" ] || [ ! -w "$d" ]; then
			die "$d holds files not owned by uid $uid (${other:-$d}), left by a gateway that ran as root. Change their owner once, e.g.: docker compose run --rm --no-deps --user 0 --entrypoint chown gateway -R $uid:$(id -g) /data /config /ca (api/docs/deployment/docker.md, \"Gateway user\")"
		fi
	done
	if [ "$mode" = internal ] && [ -d "$ca_dir" ] && [ ! -w "$ca_dir" ]; then
		echo "openctem-gateway: WARNING: $ca_dir is not writable by uid $uid, so the internal CA root is not exported there; chown it to $uid:$(id -g)" >&2
	fi
fi

# The internal CA's root certificate, copied where the operator (and sensors)
# can read it. Caddy writes its copy 0600 under /data; sensors need a
# world-readable file. Written atomically, refreshed if the CA changes.
export_root_ca() {
	src="$data_dir/caddy/pki/authorities/local/root.crt"
	dst="$ca_dir/openctem-root-ca.crt"
	i=0
	while [ ! -s "$src" ]; do
		i=$((i + 1))
		[ "$i" -le 120 ] || {
			echo "openctem-gateway: internal CA root not created after 120s; not exported" >&2
			return 0
		}
		sleep 1
	done
	if ! cmp -s "$src" "$dst" 2>/dev/null; then
		cp "$src" "$dst.tmp" && chmod 0644 "$dst.tmp" && mv -f "$dst.tmp" "$dst" &&
			echo "openctem-gateway: internal CA root certificate exported to $dst (mounted from the host); sensors trust it through SSL_CERT_DIR (or SSL_CERT_FILE)"
	fi
}

if [ "$mode" = internal ] && [ -d "$ca_dir" ]; then
	export_root_ca &
fi

if [ "$#" -gt 0 ]; then
	exec "$@"
fi
exec caddy run --config "$gateway_dir/Caddyfile" --adapter caddyfile
