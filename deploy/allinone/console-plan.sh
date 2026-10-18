#!/bin/sh
# Whether the platform console runs in this container, and where it listens.
# Sourced by supervise.sh, healthcheck.sh and the unit test.
#
# The API decides "is this client on an allowed admin network" from the peer
# address of the request. The console is the only caller of the API's console
# listener, so the API sees the console's address, not the browser's, unless a
# trusted proxy in front of the console forwards it. Only the gateway does that,
# and only on GATEWAY=on. So:
#   - the console always binds to loopback (console_host);
#   - with GATEWAY=off it does not run unless the operator opts in with
#     OPENCTEM_CONSOLE_STANDALONE=true (they then front it themselves on the
#     same network namespace and forward the client address).
console_host() { echo 127.0.0.1; }

console_enabled() {
  [ "${OPENCTEM_ADMIN_SITE:-port}" != off ] || return 1
  [ "${GATEWAY:-on}" = on ] && return 0
  [ "${OPENCTEM_CONSOLE_STANDALONE:-false}" = true ]
}

# The console settings the API must agree with the gateway on, derived from the
# gateway's own variables so each is set once (supervise.sh exports them for
# the API unless the operator set the API's variable explicitly).
#
# console_public_url: the console's public origin (ADMIN_PUBLIC_URL), the
# WebAuthn relying party of its security keys. Browsers always see HTTPS.
# Prints nothing when the console is off or the origin is not known (port mode
# behind your own TLS proxy, TLS mode http: the host is the proxy's).
console_public_url() {
  case "${OPENCTEM_ADMIN_SITE:-port}" in
    host) [ -z "${OPENCTEM_ADMIN_HOST:-}" ] || echo "https://${OPENCTEM_ADMIN_HOST}" ;;
    port)
      [ "${OPENCTEM_TLS_MODE:-internal}" != http ] || return 0
      [ -z "${OPENCTEM_HOSTNAME:-}" ] || echo "https://${OPENCTEM_HOSTNAME}:${OPENCTEM_ADMIN_PORT:-8443}"
      ;;
  esac
}

# console_allowed_cidrs: the gateway's OPENCTEM_ADMIN_ALLOWED_CIDRS (space
# separated) as the API's comma-separated ADMIN_ALLOWED_CIDRS. Prints nothing
# when the gateway variable is unset: both then default to the same private
# networks.
console_allowed_cidrs() {
  out=""
  set -f
  for c in ${OPENCTEM_ADMIN_ALLOWED_CIDRS:-}; do out="${out:+$out,}$c"; done
  set +f
  [ -z "$out" ] || echo "$out"
}
