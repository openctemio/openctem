#!/usr/bin/env bash
# openctem-supervise — PID 2 of the all-in-one image (tini is PID 1).
#
# 1. migrations: `migrate up` once, before anything serves, under a
#    non-blocking advisory lock (see migrate_locked for why not migrate's own).
# 2. starts api, web and (GATEWAY=on) the gateway: api/deploy/gateway's own
#    entrypoint.sh + Caddyfile, upstreams pointed at 127.0.0.1; every output
#    line is prefixed [api] / [web] / [gateway] on stdout/stderr.
# 3. fail-fast: when ANY child exits, the others are stopped and the container
#    exits with that child's code, so Docker/Kubernetes restart policy restarts
#    the unit. (Deliberately no in-container restart loop: a half-running
#    appliance that reports healthy is worse than a restart.)
# 4. SIGTERM/SIGINT: forwarded to all children, then waited for (graceful).
set -euo pipefail

GATEWAY="${GATEWAY:-on}"
case "$GATEWAY" in on|off) ;; *) echo "[supervise] GATEWAY must be on|off, got '$GATEWAY'" >&2; exit 64 ;; esac

# The gateway's entrypoint refuses incomplete TLS settings too; checking here
# first fails before migrations run and says which variable is missing.
if [ "$GATEWAY" = on ] && [ "${OPENCTEM_TLS_MODE:-internal}" != http ] && [ -z "${OPENCTEM_HOSTNAME:-}" ]; then
  echo "[supervise] GATEWAY=on needs OPENCTEM_HOSTNAME: the DNS name or IP address browsers and sensors use (or GATEWAY=off)" >&2
  exit 64
fi

log() { printf '[supervise] %s\n' "$*"; }
prefix() { local tag="$1"; while IFS= read -r line || [ -n "$line" ]; do printf '[%s] %s\n' "$tag" "$line"; done; }

db_url() {
  if [ -n "${DATABASE_URL:-}" ]; then printf '%s' "$DATABASE_URL"; return; fi
  printf 'postgres://%s:%s@%s:%s/%s?sslmode=%s' \
    "${DB_USER:-openctem}" "${DB_PASSWORD:-}" "${DB_HOST:-postgres}" "${DB_PORT:-5432}" \
    "${DB_NAME:-openctem}" "${DB_SSLMODE:-disable}"
}

# Migrations connect as the schema owner (D-6, api/docs/deployment/database-roles.md):
# DATABASE_MIGRATE_URL, or DB_MIGRATE_USER/DB_MIGRATE_PASSWORD, and the API keeps
# the least-privilege DB_USER. Without either, migrations use DB_USER as before.
migrate_url() {
  if [ -n "${DATABASE_MIGRATE_URL:-}" ]; then printf '%s' "$DATABASE_MIGRATE_URL"; return; fi
  if [ -z "${DB_MIGRATE_USER:-}" ]; then db_url; return; fi
  printf 'postgres://%s:%s@%s:%s/%s?sslmode=%s' \
    "${DB_MIGRATE_USER}" "${DB_MIGRATE_PASSWORD:-}" "${DB_HOST:-postgres}" "${DB_PORT:-5432}" \
    "${DB_NAME:-openctem}" "${DB_SSLMODE:-disable}"
}

# Migrations under a lock that NOBODY WAITS ON INSIDE POSTGRES.
# golang-migrate's own lock is a blocking pg_advisory_lock(): a second replica
# sits in a running statement, and CREATE INDEX CONCURRENTLY (e.g. 000143) waits
# for every open snapshot, including that waiter -> "deadlock detected" and a
# DIRTY schema. Reproduced in the rehearsal with two replicas on an empty DB.
# So replicas poll pg_try_advisory_lock() from an idle psql session (an idle
# session holds no snapshot); only the holder runs migrate.
MIGRATE_LOCK_KEY=7402159 # arbitrary; must stay constant across versions
migrate_locked() {
  local got=f i rc=0 fd
  for i in $(seq 1 150); do
    # (Re)open the session if there is none: the DB may not be up yet.
    if [ -z "${PSQL_PID:-}" ] || ! kill -0 "$PSQL_PID" 2>/dev/null; then
      coproc PSQL { psql "$(migrate_url)" -qtAX 2>&1; }
    fi
    fd="${PSQL[1]:-}"
    got=error
    if [ -n "$fd" ] && { echo "SELECT pg_try_advisory_lock(${MIGRATE_LOCK_KEY});" >&"$fd"; } 2>/dev/null; then
      IFS= read -r -t 10 got <&"${PSQL[0]}" || got=error
    fi
    [ "$got" = t ] && break
    [ $((i % 5)) = 1 ] && log "waiting for the migration lock (${got}): another replica is migrating, or the database is not up"
    sleep 2
  done
  if [ "$got" != t ]; then log "could not take the migration lock"; return 1; fi
  log "migration lock held; applying migrations"
  # openctem-migrate: migrate, plus what to do with a database older than the
  # migration baseline (api/scripts/migrate-entrypoint.sh).
  openctem-migrate -path /opt/openctem/api/migrations -database "$(migrate_url)" up 2>&1 | prefix migrate || rc=$?
  fd="${PSQL[1]:-}"
  [ -n "$fd" ] && { echo "SELECT pg_advisory_unlock(${MIGRATE_LOCK_KEY});" >&"$fd"; } 2>/dev/null
  kill "$PSQL_PID" 2>/dev/null || true; wait "$PSQL_PID" 2>/dev/null || true
  return "$rc"
}

if [ "${MIGRATE_ON_START:-true}" = "true" ]; then
  migrate_locked || { log "migrations failed; not starting (a dirty schema needs 'migrate force' by an operator)"; exit 1; }
fi

if [ "$GATEWAY" = on ]; then
  # Only the gateway listens on a routable address.
  export SERVER_HOST="${SERVER_HOST:-127.0.0.1}" WEB_HOSTNAME="${WEB_HOSTNAME:-127.0.0.1}"
  # The gateway and the web proxy both reach the API from 127.0.0.1, and only
  # they can (nothing else is bound there), so the API believes their
  # X-Real-IP / X-Forwarded-For and the web passes the gateway's on: the audit
  # log, rate limits and IP allowlists see the real client. Same rule as the
  # split deployment's SERVER_TRUSTED_PROXIES=<gateway>,<web>.
  export SERVER_TRUSTED_PROXIES="${SERVER_TRUSTED_PROXIES:-127.0.0.1/32}"
  export TRUST_PROXY_HEADERS="${TRUST_PROXY_HEADERS:-true}"
  # Browsers always arrive over HTTPS (or the operator's TLS proxy in mode http).
  export SECURE_COOKIES="${SECURE_COOKIES:-true}" AUTH_COOKIE_SECURE="${AUTH_COOKIE_SECURE:-true}"
else
  export SERVER_HOST="${SERVER_HOST:-0.0.0.0}" WEB_HOSTNAME="${WEB_HOSTNAME:-0.0.0.0}"
fi
export SERVER_PORT="${SERVER_PORT:-8080}"

declare -A PIDS=()
start() { # start <tag> <dir> <cmd...>
  local tag="$1" dir="$2"; shift 2
  ( cd "$dir" && exec "$@" ) > >(prefix "$tag") 2> >(prefix "$tag" >&2) &
  PIDS[$tag]=$!
  log "started $tag (pid ${PIDS[$tag]})"
}

stop_all() {
  local sig="${1:-TERM}"
  for tag in "${!PIDS[@]}"; do kill -s "$sig" "${PIDS[$tag]}" 2>/dev/null || true; done
}
on_signal() { log "signal received; stopping children"; stop_all TERM; wait; exit 143; }
trap on_signal TERM INT

start api /opt/openctem/api ./server
start web /opt/openctem/web env PORT=3000 HOSTNAME="$WEB_HOSTNAME" node server-with-ws.mjs
if [ "$GATEWAY" = on ]; then
  # api/deploy/gateway/entrypoint.sh: validates OPENCTEM_TLS_MODE and its
  # inputs, exports the internal CA root to $OPENCTEM_CA_EXPORT_DIR, then runs
  # Caddy with the shared Caddyfile (OPENCTEM_{API,WEB}_UPSTREAM = 127.0.0.1).
  start gateway /opt/openctem /bin/sh /etc/caddy/entrypoint.sh
fi

# First child to exit decides the container's fate.
set +e
wait -n "${PIDS[@]}"
code=$?
set -e
for tag in "${!PIDS[@]}"; do
  if ! kill -0 "${PIDS[$tag]}" 2>/dev/null; then log "$tag exited (code $code); stopping the others"; fi
done
stop_all TERM
( sleep 20; stop_all KILL ) & killer=$!
wait "${PIDS[@]}" 2>/dev/null || true
kill "$killer" 2>/dev/null || true
exit "$code"
