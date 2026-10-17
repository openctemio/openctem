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
