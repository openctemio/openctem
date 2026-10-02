#!/bin/sh
# Healthy only if EVERY process this container runs answers.
set -e
wget -q -T 5 -O /dev/null "http://127.0.0.1:${SERVER_PORT:-8080}/health"
wget -q -T 5 -O /dev/null http://127.0.0.1:3000/api/health
[ "${GATEWAY:-on}" = on ] || exit 0

# The gateway's admin API (bound to 127.0.0.1:2019 by the shared Caddyfile).
wget -q -T 5 -O /dev/null http://127.0.0.1:2019/config/
# And a request routed the way a sensor's is (/health -> API), through TLS.
# The site is https://$OPENCTEM_HOSTNAME, so send that Host; with no SNI (an IP)
# the gateway serves that site's certificate (default_sni).
case "${OPENCTEM_TLS_MODE:-internal}" in
internal | files)
  wget -q -T 5 --no-check-certificate --header "Host: ${OPENCTEM_HOSTNAME}" -O /dev/null https://127.0.0.1:443/health ;;
http)
  wget -q -T 5 -O /dev/null http://127.0.0.1:80/health ;;
acme) : ;; # the public certificate may still be pending; the admin API answered
esac
