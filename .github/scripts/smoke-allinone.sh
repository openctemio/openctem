#!/usr/bin/env bash
# smoke-allinone.sh <image-ref>
#
# Starts the all-in-one image twice against an EXTERNAL Postgres + Redis and
# waits for Docker's own healthcheck (which covers every process):
#   GATEWAY=off -> :8080 /health and :3000 /api/health answer
#   GATEWAY=on  -> :443 /health (API) and /login (web) answer through the
#                  shared gateway (api/deploy/gateway, TLS mode internal),
#                  /metrics is blocked, 8080/3000 are bound to 127.0.0.1 only
#   GATEWAY=on without OPENCTEM_HOSTNAME -> refuses to start (exit 64)
# Environment:
#   SMOKE_NETWORK  docker network to join (default: host — CI service containers)
#   DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME REDIS_HOST REDIS_PORT
#   (CI and 02-verify run Postgres with trust auth: DB_PASSWORD stays empty)
set -euo pipefail
img="$1"
net="${SMOKE_NETWORK:-host}"
name="openctem-smoke-$$"
common=(
  --network "$net"
  -e APP_ENV=development -e AUTH_PROVIDER=local -e AUTH_REQUIRE_EMAIL_VERIFICATION=false
  -e AUTH_JWT_SECRET="$(openssl rand -hex 32)" -e APP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
  -e DB_HOST="${DB_HOST:-localhost}" -e DB_PORT="${DB_PORT:-5432}" -e DB_USER="${DB_USER:-openctem}"
  -e DB_PASSWORD="${DB_PASSWORD:-}" -e DB_NAME="${DB_NAME:-app_smoke}" -e DB_SSLMODE=disable
  -e REDIS_HOST="${REDIS_HOST:-localhost}" -e REDIS_PORT="${REDIS_PORT:-6379}"
)

wait_healthy() {
  local c="$1"
  for _ in $(seq 1 90); do
    s=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.State.Status}}' "$c")
    case "$s" in
      "healthy running") return 0 ;;
      *exited*|*dead*) break ;;
    esac
    sleep 2
  done
  echo "--- $c did not become healthy ($s); last logs:" >&2
  docker logs --tail 80 "$c" >&2 || true
  return 1
}
cleanup() { docker rm -f "$name-off" "$name-on" "$name-nohost" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== GATEWAY=off"
docker run -d --name "$name-off" "${common[@]}" -e GATEWAY=off "$img" >/dev/null
wait_healthy "$name-off"
docker exec "$name-off" wget -qO- http://127.0.0.1:8080/health; echo
docker exec "$name-off" wget -qO /dev/null http://127.0.0.1:3000/login && echo "  ok    web /login on :3000 -> 200"
docker exec "$name-off" sh -c 'wget -qO- http://127.0.0.1:8080/openapi.yaml | grep -q "^paths:"' && echo "  ok    api /openapi.yaml on :8080 -> spec"
docker exec "$name-off" sh -c 'netstat -ltn 2>/dev/null | grep -E ":(8080|3000|443) " || true'
docker logs "$name-off" 2>&1 | grep -oE '^\[(supervise|migrate|api|web|gateway)\]' | sort | uniq -c
docker rm -f "$name-off" >/dev/null

echo "== GATEWAY=on"
docker run -d --name "$name-on" "${common[@]}" -e GATEWAY=on -e OPENCTEM_HOSTNAME=localhost "$img" >/dev/null
wait_healthy "$name-on"
# Status code of a request through the gateway (site https://localhost; no SNI
# for an IP, so the gateway's default_sni serves that site's certificate).
status() { { docker exec "$name-on" wget -S -q --no-check-certificate --header 'Host: localhost' -O /dev/null "https://127.0.0.1:443$1" 2>&1 || true; } | awk '/HTTP\//{c=$2} END{print c}'; }
expect() { local got; got=$(status "$1"); if [ "$got" = "$2" ]; then echo "  ok    $1 via gateway :443 -> $got ($3)"; else echo "  FAIL  $1 via gateway :443 -> '$got', want $2 ($3)" >&2; exit 1; fi; }
docker exec "$name-on" wget -qO- --no-check-certificate --header 'Host: localhost' https://127.0.0.1:443/health; echo
expect /health 200 api
expect /login 200 web
expect /metrics 404 "blocked by the gateway"
# Only the gateway is routable; api and web listen on loopback.
listen=$(docker exec "$name-on" sh -c 'netstat -ltn 2>/dev/null || ss -ltn')
echo "$listen" | grep -E ':(8080|3000|443|80|2019) ' || true
if echo "$listen" | grep -E '(0\.0\.0\.0|::):(8080|3000) '; then echo "api/web reachable beyond loopback with GATEWAY=on" >&2; exit 1; fi
docker exec "$name-on" test -s /data/ca/openctem-root-ca.crt || { echo "internal CA root not exported to /data/ca" >&2; exit 1; }
echo "  ok    internal CA root exported to /data/ca/openctem-root-ca.crt"
docker logs "$name-on" 2>&1 | grep -oE '^\[(supervise|migrate|api|web|gateway)\]' | sort | uniq -c
docker rm -f "$name-on" >/dev/null

echo "== GATEWAY=on without OPENCTEM_HOSTNAME refuses to start"
set +e
docker run --name "$name-nohost" "${common[@]}" -e GATEWAY=on "$img" >/dev/null 2>&1; rc=$?
set -e
docker logs "$name-nohost" 2>&1 | tail -1; docker rm -f "$name-nohost" >/dev/null 2>&1 || true
[ "$rc" = 64 ] || { echo "expected exit 64, got $rc" >&2; exit 1; }
echo "smoke-allinone: OK"
