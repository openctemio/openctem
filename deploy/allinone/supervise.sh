#!/usr/bin/env bash
# openctem-supervise — PID 2 of the all-in-one image (tini is PID 1).
#
# 1. migrations: `migrate up` once, before anything serves, under a
#    non-blocking advisory lock (see migrate_locked for why not migrate's own).
# 2. starts api, web, the platform console (unless OPENCTEM_ADMIN_SITE=off)
#    and (GATEWAY=on) the gateway: api/deploy/gateway's own
#    entrypoint.sh + Caddyfile, upstreams pointed at 127.0.0.1; every output
#    line is prefixed [api] / [web] / [gateway] on stdout/stderr.
# 3. fail-fast: when ANY child exits, the others are stopped and the container
#    exits with that child's code, so Docker/Kubernetes restart policy restarts
#    the unit. (Deliberately no in-container restart loop: a half-running
#    appliance that reports healthy is worse than a restart.)
# 4. SIGTERM/SIGINT: forwarded to all children, then waited for (graceful).
# 5. isolation: started as root (the image default), the supervisor prepares
#    the data directories and starts each child under its own uid with
#    no-new-privileges and no capabilities (api, web, console, gateway), and
#    each child gets only its own environment (child-env.sh). Only the
#    supervisor ever holds the schema owner's credentials, and it passes them
#    to psql/migrate in PGPASSWORD, never on a command line. Started as a
#    non-root uid (e.g. --user 1001, or a Kubernetes runAsNonRoot policy) every
#    child shares that uid: one trust domain, fit for evaluation and small
#    single-tenant installs only (api/docs/deployment/docker.md, "All-in-one
#    image: process isolation").
set -euo pipefail

GATEWAY="${GATEWAY:-on}"
. /usr/local/bin/openctem-console-plan
. /usr/local/bin/openctem-child-env
case "$GATEWAY" in on|off) ;; *) echo "[supervise] GATEWAY must be on|off, got '$GATEWAY'" >&2; exit 64 ;; esac

# The gateway's entrypoint refuses incomplete TLS settings too; checking here
# first fails before migrations run and says which variable is missing.
if [ "$GATEWAY" = on ] && [ "${OPENCTEM_TLS_MODE:-internal}" != http ] && [ -z "${OPENCTEM_HOSTNAME:-}" ]; then
  echo "[supervise] GATEWAY=on needs OPENCTEM_HOSTNAME: the DNS name or IP address browsers and sensors use (or GATEWAY=off)" >&2
  exit 64
fi

log() { printf '[supervise] %s\n' "$*"; }
prefix() { local tag="$1"; while IFS= read -r line || [ -n "$line" ]; do printf '[%s] %s\n' "$tag" "$line"; done; }

# Who runs what. As root, each child gets its own user (created in the image);
# otherwise everything runs as the uid the container was started with.
ISOLATED=false
if [ "$(id -u)" = 0 ]; then
  ISOLATED=true
  if ! setpriv --reuid=nextjs --regid=nodejs --clear-groups true 2>/dev/null; then
    echo "[supervise] started as root but cannot switch users (the container needs CAP_SETUID and CAP_SETGID, which Docker grants by default); or start it as --user 1001 to run every process under one uid" >&2
    exit 64
  fi
else
  log "WARNING: running every process as uid $(id -u): api, web, console and gateway share one trust domain (a compromised web process can read the API's secrets). Start the container as root (the image default) to run each under its own uid; this mode suits evaluation and small single-tenant installs, never a multi-tenant service."
fi
child_user() { # child_user <role> -> user:group
  case "$1" in
    api) echo openctem-api:openctem-api ;;
    web) echo nextjs:nodejs ;;
    console) echo openctem-console:openctem-console ;;
    gateway) echo openctem-gateway:openctem-gateway ;;
    signer) echo openctem-signer:openctem-signer ;;
    *) echo "[supervise] internal error: no user defined for role '$1'" >&2; return 1 ;;
  esac
}

# own <dir> <role> <mode>: dir exists, belongs to <role>'s user (recursively,
# once: only when the top is not theirs yet, e.g. a volume from a release that
# ran everything as uid 1001) and has <mode>.
# Runs as root on directories a process could write before, so it never
# follows a symbolic link: a planted link must not hand a root-owned file
# (the supervisor itself, say) to a process's user.
own() {
  local dir="$1" ug; ug="$(child_user "$2")" || exit 1
  if [ -L "$dir" ]; then echo "[supervise] $dir is a symbolic link; refusing to change its owner" >&2; exit 1; fi
  mkdir -p "$dir"
  if [ "$(stat -c %U:%G "$dir")" != "$ug" ]; then chown -hR "$ug" "$dir"; fi
  chmod "$3" "$dir"
}

# The gateway keeps Caddy's storage in /data/gateway (it used /data until this
# release): its entrypoint refuses a data directory holding files it does not
# own, and /data also holds the API's attachments and sensor CA.
case "${XDG_DATA_HOME:-}" in "" | /data | /data/) export XDG_DATA_HOME=/data/gateway ;; esac
if [ -d /data/caddy ] && [ ! -e "$XDG_DATA_HOME/caddy" ] && [ "$XDG_DATA_HOME" = /data/gateway ]; then
  mkdir -p "$XDG_DATA_HOME" && mv /data/caddy "$XDG_DATA_HOME/caddy" && log "moved the gateway's storage from /data/caddy to $XDG_DATA_HOME/caddy"
fi
mkdir -p "$XDG_DATA_HOME"

# The gateway's admin API on a unix socket in a directory only the gateway
# can open, not on 127.0.0.1:2019 where any process in the container (all
# share one network namespace) could load a new configuration.
GATEWAY_RUN="$(mktemp -d /tmp/openctem-gateway.XXXXXX)"
export OPENCTEM_CADDY_ADMIN="unix/$GATEWAY_RUN/admin.sock|0600"

if [ "$ISOLATED" = true ]; then
  chown root:root /data && chmod 0755 /data
  case "${STORAGE_LOCAL_PATH:-/data/attachments}" in /data/*) own "${STORAGE_LOCAL_PATH:-/data/attachments}" api 0700 ;; esac
  case "${SENSOR_MTLS_CA_DIR:-}" in /data/*) own "$SENSOR_MTLS_CA_DIR" api 0700 ;; esac
  case "$XDG_DATA_HOME" in /data/*) own "$XDG_DATA_HOME" gateway 0700 ;; esac
  case "${OPENCTEM_CA_EXPORT_DIR:-}" in /data/*) own "$OPENCTEM_CA_EXPORT_DIR" gateway 0755 ;; esac
  own "${XDG_CONFIG_HOME:-/config}" gateway 0700
  own "$GATEWAY_RUN" gateway 0700
  own /opt/openctem/web/.next/cache web 0700
  own /opt/openctem/console/console/.next/cache console 0700
fi

# Percent-encodes one URL part (user or database name): a value with @ : / ?
# # or % in it otherwise breaks the URL or changes what it means.
urlenc() (
  LC_ALL=C
  s=$1
  while [ -n "$s" ]; do
    rest=${s#?}
    c=${s%"$rest"}
    s=$rest
    case $c in
      [A-Za-z0-9._~-]) printf '%s' "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
)

# Decodes %XX escapes (a password taken out of a URL).
urldec() (
  LC_ALL=C
  s=$1
  while [ -n "$s" ]; do
    case $s in
      %[0-9A-Fa-f][0-9A-Fa-f]*) printf "\\x${s:1:2}"; s=${s:3} ;;
      *) printf '%s' "${s:0:1}"; s=${s:1} ;;
    esac
  done
)

# The migrations' connection, schema owner first (D-6,
# api/docs/deployment/database-roles.md): DATABASE_MIGRATE_URL, else
# DB_MIGRATE_USER/DB_MIGRATE_PASSWORD, else (as before) the API's own DB_USER /
# DATABASE_URL. Sets MIG_URL WITHOUT the password and MIG_PASS: psql and
# migrate read the password from PGPASSWORD, so it never shows in ps or
# /proc/<pid>/cmdline.
migrate_conn() {
  local url="" user pass
  if [ -n "${DATABASE_MIGRATE_URL:-}" ]; then url="$DATABASE_MIGRATE_URL"
  elif [ -n "${DB_MIGRATE_USER:-}" ]; then user="$DB_MIGRATE_USER" pass="${DB_MIGRATE_PASSWORD:-}"
  elif [ -n "${DATABASE_URL:-}" ]; then url="$DATABASE_URL"
  else user="${DB_USER:-openctem}" pass="${DB_PASSWORD:-}"
  fi
  if [ -n "$url" ]; then
    local re='^([A-Za-z][A-Za-z0-9+.-]*://)([^:@/]*):([^@/]*)@(.*)$'
    if [[ $url =~ $re ]]; then
      MIG_URL="${BASH_REMATCH[1]}${BASH_REMATCH[2]}@${BASH_REMATCH[4]}"
      MIG_PASS="$(urldec "${BASH_REMATCH[3]}")"
    else
      MIG_URL="$url" MIG_PASS="${PGPASSWORD:-}"
    fi
    return
  fi
  MIG_URL="$(printf 'postgres://%s@%s:%s/%s?sslmode=%s' \
    "$(urlenc "$user")" "${DB_HOST:-postgres}" "${DB_PORT:-5432}" \
    "$(urlenc "${DB_NAME:-openctem}")" "${DB_SSLMODE:-disable}")"
  MIG_PASS="$pass"
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
      coproc PSQL { PGPASSWORD="$MIG_PASS" psql "$MIG_URL" -qtAX 2>&1; }
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
  PGPASSWORD="$MIG_PASS" openctem-migrate -path /opt/openctem/api/migrations -database "$MIG_URL" up 2>&1 | prefix migrate || rc=$?
  fd="${PSQL[1]:-}"
  [ -n "$fd" ] && { echo "SELECT pg_advisory_unlock(${MIGRATE_LOCK_KEY});" >&"$fd"; } 2>/dev/null
  kill "$PSQL_PID" 2>/dev/null || true; wait "$PSQL_PID" 2>/dev/null || true
  return "$rc"
}

if [ "${MIGRATE_ON_START:-true}" = "true" ]; then
  migrate_conn
  migrate_locked || { log "migrations failed; not starting (a dirty schema needs 'migrate force' by an operator)"; exit 1; }
fi
# Nothing after the migrations needs the schema owner: drop it here (the
# children never get it either, child-env.sh).
unset MIG_PASS MIG_URL DB_MIGRATE_PASSWORD DATABASE_MIGRATE_URL DB_MIGRATE_USER PGPASSWORD 2>/dev/null || true

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
# The console's Content-Security-Policy names the public origin: the API's
# APP_URL, unless set on its own.
if [ -n "${APP_URL:-}" ]; then export NEXT_PUBLIC_APP_URL="${NEXT_PUBLIC_APP_URL:-$APP_URL}"; fi

# The console's origin and allowed networks come from the gateway's variables
# (console-plan.sh), so the API agrees with the gateway without a second copy.
# An explicit ADMIN_PUBLIC_URL wins; the gateway's allow-list always applies.
if [ -z "${ADMIN_PUBLIC_URL:-}" ]; then
  url="$(console_public_url)"
  [ -z "$url" ] || export ADMIN_PUBLIC_URL="$url"
fi
cidrs="$(console_allowed_cidrs)"
[ -z "$cidrs" ] || export ADMIN_ALLOWED_CIDRS="$cidrs"

declare -A PIDS=()
start() { # start <tag> <dir> <cmd...>; <tag> is also the role (child-env.sh)
  local tag="$1" dir="$2"; shift 2
  (
    cd "$dir"
    child_env_scrub "$tag"
    if [ "$ISOLATED" = true ]; then
      local ug nnp=--no-new-privs; ug="$(child_user "$tag")" || exit 1
      [ -n "${ug%%:*}" ] && [ -n "${ug##*:}" ] || { echo "[supervise] no uid/gid for role $tag" >&2; exit 1; }
      # The gateway's Caddy binds 443 through a file capability, which
      # no-new-privileges would cancel; it still starts with none of its own.
      [ "$tag" = gateway ] && nnp=
      export HOME="$dir"
      exec setpriv --reuid="${ug%%:*}" --regid="${ug##*:}" --clear-groups --inh-caps=-all $nnp -- "$@"
    fi
    exec "$@"
  ) > >(prefix "$tag") 2> >(prefix "$tag" >&2) &
  PIDS[$tag]=$!
  log "started $tag (pid ${PIDS[$tag]})"
}

stop_all() {
  local sig="${1:-TERM}"
  for tag in "${!PIDS[@]}"; do kill -s "$sig" "${PIDS[$tag]}" 2>/dev/null || true; done
}
on_signal() { log "signal received; stopping children"; stop_all TERM; wait; exit 143; }
trap on_signal TERM INT

# The job signer (docs/architecture/job-signing.md): every job handed to a
# sensor is signed by it, and a production API refuses to start without it.
# Its key is created on first start in /data/signer (back up /data). Here it
# shares the container with the API, so it is a separate process with its
# own key file but not the separate container and user of the split
# deployment. An operator's own SIGNER_SOCKET (an external signer) wins;
# OPENCTEM_SIGNER=off starts none.
if [ -z "${SIGNER_SOCKET:-}" ] && [ "${OPENCTEM_SIGNER:-on}" = on ]; then
  mkdir -p /data/signer/keys /data/signer/state /tmp/openctem-signer
  if [ "$ISOLATED" = true ]; then
    # Key and ledger belong to the signer alone (0700): the API cannot read
    # them. The socket's directory is the one thing they share: group
    # openctem-api, setgid so the socket (0660) inherits that group.
    own /data/signer signer 0700
    own /data/signer/keys signer 0700
    own /data/signer/state signer 0700
    chown -h openctem-signer:openctem-api /tmp/openctem-signer
    chmod 2750 /tmp/openctem-signer
  else
    chmod 0700 /data/signer /data/signer/keys /data/signer/state /tmp/openctem-signer
  fi
  start signer /opt/openctem/api env SIGNER_KEY_FILE=/data/signer/keys/signer.pem SIGNER_GENERATE_KEY=true \
    SIGNER_STATE_DIR=/data/signer/state SIGNER_SOCKET=/tmp/openctem-signer/signer.sock ./openctem-signer serve
  for _ in $(seq 1 30); do
    [ -S /tmp/openctem-signer/signer.sock ] && break
    sleep 1
  done
  [ -S /tmp/openctem-signer/signer.sock ] || { log "the job signer did not start; not starting the API"; stop_all TERM; exit 1; }
  export SIGNER_SOCKET=/tmp/openctem-signer/signer.sock
fi
start api /opt/openctem/api ./server
start web /opt/openctem/web env PORT=3000 HOSTNAME="$WEB_HOSTNAME" node server-with-ws.mjs
# The platform console: its own app on :3001, talking to the API's console
# listener on loopback (ADMIN_LISTEN_ADDR). None with OPENCTEM_ADMIN_SITE=off.
# It always binds to loopback and with GATEWAY=off does not run unless
# OPENCTEM_CONSOLE_STANDALONE=true (console-plan.sh says why).
if console_enabled; then
  start console /opt/openctem/console env PORT=3001 HOSTNAME="$(console_host)" \
    ADMIN_API_URL="${ADMIN_API_URL:-http://${ADMIN_LISTEN_ADDR:-127.0.0.1:8080}}" node console/server.js
fi
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
