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
