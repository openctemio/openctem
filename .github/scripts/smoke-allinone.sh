#!/usr/bin/env bash
# smoke-allinone.sh <image-ref>
#
# Starts the all-in-one image twice against an EXTERNAL Postgres + Redis and
# waits for Docker's own healthcheck (which covers every process):
#   GATEWAY=off -> :8080 /health and :3000 /api/health answer; no console on :3001
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
  -e AUTH_JWT_SECRET="$(openssl rand -hex 32)" -e APP_ENCRYPTION_KEY="$(openssl rand -hex 32)" -e FINGERPRINT_KEY="$(openssl rand -hex 32)"
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
if docker exec "$name-off" wget -q -T 3 -O /dev/null http://127.0.0.1:3001/login 2>/dev/null; then echo "  FAIL  console runs with GATEWAY=off (it would see every client as loopback)" >&2; exit 1; fi
echo "  ok    no console with GATEWAY=off"
docker exec "$name-off" sh -c 'wget -qO- http://127.0.0.1:8080/openapi.yaml | grep -q "^paths:"' && echo "  ok    api /openapi.yaml on :8080 -> spec"
docker exec "$name-off" sh -c 'netstat -ltn 2>/dev/null | grep -E ":(8080|3000|443) " || true'
docker logs "$name-off" 2>&1 | grep -oE '^\[(supervise|migrate|api|web|console|gateway)\]' | sort | uniq -c
docker rm -f "$name-off" >/dev/null

echo "== GATEWAY=on"
# The schema owner is the app role here; set through DB_MIGRATE_* so the run
# proves those never reach a serving process.
docker run -d --name "$name-on" "${common[@]}" -e GATEWAY=on -e OPENCTEM_HOSTNAME=localhost \
  -e DB_MIGRATE_USER="${DB_USER:-openctem}" -e DB_MIGRATE_PASSWORD="${DB_PASSWORD:-}" "$img" >/dev/null
wait_healthy "$name-on"
# Status code of a request through the gateway (site https://localhost; no SNI
# for an IP, so the gateway's default_sni serves that site's certificate).
status() { { docker exec "$name-on" wget -S -q --no-check-certificate --header 'Host: localhost' -O /dev/null "https://127.0.0.1:443$1" 2>&1 || true; } | awk '/HTTP\//{c=$2} END{print c}'; }
expect() { local got; got=$(status "$1"); if [ "$got" = "$2" ]; then echo "  ok    $1 via gateway :443 -> $got ($3)"; else echo "  FAIL  $1 via gateway :443 -> '$got', want $2 ($3)" >&2; exit 1; fi; }
docker exec "$name-on" wget -qO- --no-check-certificate --header 'Host: localhost' https://127.0.0.1:443/health; echo
expect /health 200 api
expect /login 200 web
expect /metrics 404 "blocked by the gateway"
expect /api/v1/admin/auth/validate 404 "no console API on the main site"
# The platform console's own site (OPENCTEM_ADMIN_SITE=port): its root, from loopback (an allowed network).
cstatus() { { docker exec "$name-on" wget -S -q --no-check-certificate --header 'Host: localhost:8443' -O /dev/null "https://127.0.0.1:8443$1" 2>&1 || true; } | awk '/HTTP\//{c=$2} END{print c}'; }
for p in / /login; do
  got=$(cstatus "$p")
  if [ "$got" = 200 ]; then echo "  ok    $p via console site :8443 -> 200"; else echo "  FAIL  $p via console site :8443 -> '$got', want 200" >&2; exit 1; fi
done
# Only the gateway is routable; api and web listen on loopback.
listen=$(docker exec "$name-on" sh -c 'netstat -ltn 2>/dev/null || ss -ltn')
echo "$listen" | grep -E ':(8080|8081|3000|3001|443|8443|80|2019) ' || true
if echo "$listen" | grep -E '(0\.0\.0\.0|::):(8080|8081|3000|3001) '; then echo "api/web/console reachable beyond loopback with GATEWAY=on" >&2; exit 1; fi
if echo "$listen" | grep -E ':2019 '; then echo "the gateway's admin API listens on TCP (any process could reconfigure it)" >&2; exit 1; fi
echo "  ok    gateway admin API not on TCP"
# Process isolation: each process under its own uid, and only its own
# environment (supervise.sh, child-env.sh).
# Zombies are skipped: the gateway's entrypoint leaves a short-lived sh that
# Caddy (its parent after exec) never reaps, and a zombie has no environment.
procs=$(docker exec "$name-on" sh -c 'for p in /proc/[0-9]*; do u=$(awk "/^Uid:/{print \$2}" $p/status 2>/dev/null) && ! grep -q "^State:.Z" $p/status 2>/dev/null && echo "${p#/proc/} $u $(cat $p/comm 2>/dev/null)"; done')
# api 1002, web 1001, console 1003, gateway 1004 (Node may rename its
# process, so only the uid is matched there).
echo "$procs" | grep -q " 1002 server\$" || { echo "the API does not run as uid 1002; got:" >&2; echo "$procs" >&2; exit 1; }
for uid in 1001 1003 1004; do
  echo "$procs" | awk -v u="$uid" '$2==u{f=1} END{exit !f}' || { echo "no process runs as uid $uid; got:" >&2; echo "$procs" >&2; exit 1; }
done
echo "  ok    api, web, console and gateway each run under their own uid"
# The job signer runs as its own uid 1005; the API (1002) reaches its socket
# but can read neither its key nor its ledger.
echo "$procs" | grep -q " 1005 openctem-signer\$" || { echo "the job signer does not run as uid 1005; got:" >&2; echo "$procs" >&2; exit 1; }
if docker exec -u 1002:1002 "$name-on" sh -c 'cat /data/signer/keys/signer.pem >/dev/null 2>&1 || ls /data/signer/state >/dev/null 2>&1'; then
  echo "  FAIL  the API uid can read the job signer's key or state" >&2; exit 1
fi
docker exec -u 1002:1002 "$name-on" sh -c 'test -r /tmp/openctem-signer/signer.sock && test -w /tmp/openctem-signer/signer.sock' \
  || { echo "  FAIL  the API uid cannot open the job signer's socket" >&2; exit 1; }
echo "  ok    the job signer runs under its own uid; the API reaches its socket but not its key"
api_pid=$(echo "$procs" | awk '$2==1002 && $3=="server"{print $1; exit}')
# environ_of <uid> <pid>: a process's environment, read with CAP_SYS_PTRACE
# (--privileged): Caddy carries a file capability, which makes its process
# non-dumpable, so not even its own uid can read /proc/<pid>/environ. An
# unreadable one fails the test instead of passing it as "empty".
environ_of() {
  local e; e=$(docker exec --privileged -u 0 "$name-on" sh -c "tr '\\0' '\\n' </proc/$2/environ")
  echo "$e" | grep -q '^PATH=' || { echo "cannot read the environment of pid $2 as uid $1" >&2; exit 1; }
  echo "$e"
}
secrets='^(DB_[A-Z_]*PASSWORD|DATABASE_[A-Z_]*URL|DB_MIGRATE_[A-Z]*|APP_ENCRYPTION_KEY|FINGERPRINT_KEY|AUTH_JWT_SECRET|REDIS_PASSWORD|PGPASSWORD)='
for uid in 1001 1003 1004; do
  for pid in $(echo "$procs" | awk -v u="$uid" '$2==u{print $1}'); do
    env_dump=$(environ_of "$uid" "$pid")
    leaked=$(echo "$env_dump" | grep -oE "$secrets" || true)
    [ -z "$leaked" ] || { echo "uid $uid (pid $pid) holds secrets: $leaked" >&2; exit 1; }
  done
done
echo "  ok    web, console and gateway hold no database password or key"
env_dump=$(environ_of 1002 "$api_pid")
echo "$env_dump" | grep -q '^DB_PASSWORD=' || { echo "the API lost its own DB_PASSWORD" >&2; exit 1; }
leaked=$(echo "$env_dump" | grep -oE '^(DB_MIGRATE_[A-Z]*|DATABASE_MIGRATE_URL|PGPASSWORD)=' || true)
[ -z "$leaked" ] || { echo "the API holds the schema owner's credentials: $leaked" >&2; exit 1; }
echo "  ok    the API does not hold the schema owner's credentials"
if docker exec -u 1001 "$name-on" sh -c "cat /proc/$api_pid/environ" >/dev/null 2>&1; then echo "the web uid can read the API's environment" >&2; exit 1; fi
if docker exec -u 1001 "$name-on" sh -c 'ls /tmp/openctem-gateway.*/' >/dev/null 2>&1; then echo "the web uid can reach the gateway's admin socket" >&2; exit 1; fi
echo "  ok    the web uid cannot read the API's environment or reach the gateway admin socket"
docker exec "$name-on" test -s /data/ca/openctem-root-ca.crt || { echo "internal CA root not exported to /data/ca" >&2; exit 1; }
echo "  ok    internal CA root exported to /data/ca/openctem-root-ca.crt"
docker logs "$name-on" 2>&1 | grep -oE '^\[(supervise|migrate|api|web|console|gateway)\]' | sort | uniq -c
docker rm -f "$name-on" >/dev/null

echo "== GATEWAY=on without OPENCTEM_HOSTNAME refuses to start"
set +e
docker run --name "$name-nohost" "${common[@]}" -e GATEWAY=on "$img" >/dev/null 2>&1; rc=$?
set -e
docker logs "$name-nohost" 2>&1 | tail -1; docker rm -f "$name-nohost" >/dev/null 2>&1 || true
[ "$rc" = 64 ] || { echo "expected exit 64, got $rc" >&2; exit 1; }
echo "smoke-allinone: OK"
