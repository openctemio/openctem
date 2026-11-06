#!/usr/bin/env bash
# Starts the stack the console suite runs against and creates its administrator:
#
#   migrations -> API (main listener + console listener) -> bootstrap-admin
#   -> `next start console`
#
# Postgres and Redis already run (the workflow's service containers, or the
# containers a developer started, see ../README.md). Everything this script
# starts listens on 127.0.0.1 only; PIDs go to $STACK_DIR/pids and the logs to
# $STACK_DIR/*.log. It prints the CONSOLE_E2E_* variables the suite reads to
# $STACK_DIR/env (and, in GitHub Actions, to $GITHUB_ENV, masked).
#
# Env (defaults suit the workflow):
#   BIN_DIR       server, openctem-migrate, bootstrap-admin (link to server)
#   STACK_DIR     scratch dir for logs, pids and the env file
#   DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME   Postgres
#   REDIS_HOST REDIS_PORT REDIS_PASSWORD          Redis
#   API_PORT ADMIN_PORT CONSOLE_PORT              8080, 8081, 3001
set -euo pipefail

root="$(cd "$(dirname "$0")/../../../.." && pwd)"
BIN_DIR="${BIN_DIR:?set BIN_DIR}"
STACK_DIR="${STACK_DIR:?set STACK_DIR}"
DB_HOST="${DB_HOST:-127.0.0.1}" DB_PORT="${DB_PORT:-5432}" DB_USER="${DB_USER:-openctem}"
DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -hex 16)}" DB_NAME="${DB_NAME:-openctem}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}" REDIS_PORT="${REDIS_PORT:-6379}" REDIS_PASSWORD="${REDIS_PASSWORD:-}"
API_PORT="${API_PORT:-8080}" ADMIN_PORT="${ADMIN_PORT:-8081}" CONSOLE_PORT="${CONSOLE_PORT:-3001}"

for port in "$API_PORT" "$ADMIN_PORT" "$CONSOLE_PORT"; do
  if ss -ltn | grep -q "[:.]${port} "; then echo "start-stack: port $port is already in use" >&2; exit 1; fi
done
mkdir -p "$STACK_DIR"
: >"$STACK_DIR/pids"
log() { echo "start-stack: $*" >&2; }
rnd() { openssl rand -hex "$1"; }

DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"
ADMIN_PASSWORD="$(rnd 12)Q$(rnd 4)"
export AUTH_JWT_SECRET APP_ENCRYPTION_KEY FINGERPRINT_KEY
AUTH_JWT_SECRET="$(rnd 32)" APP_ENCRYPTION_KEY="$(rnd 32)" FINGERPRINT_KEY="$(rnd 32)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  for v in "$ADMIN_PASSWORD" "$AUTH_JWT_SECRET" "$APP_ENCRYPTION_KEY" "$FINGERPRINT_KEY"; do echo "::add-mask::$v"; done
fi

log "migrations"
"$BIN_DIR/openctem-migrate" -path="$root/server/migrations" -database "$DATABASE_URL" up >"$STACK_DIR/migrate.log" 2>&1

# The console's origin is the one the browser uses; the API checks it.
CONSOLE_URL="http://127.0.0.1:${CONSOLE_PORT}"
api_env=(
  APP_ENV=staging APP_URL="$CONSOLE_URL" ADMIN_PUBLIC_URL="$CONSOLE_URL"
  CORS_ALLOWED_ORIGINS="$CONSOLE_URL" AUTH_COOKIE_SECURE=false
  SERVER_HOST=127.0.0.1 SERVER_PORT="$API_PORT" ADMIN_LISTEN_ADDR="127.0.0.1:${ADMIN_PORT}"
  DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" DB_NAME="$DB_NAME" DB_SSLMODE=disable
  REDIS_HOST="$REDIS_HOST" REDIS_PORT="$REDIS_PORT" REDIS_PASSWORD="$REDIS_PASSWORD"
  LOG_LEVEL=info LOG_FORMAT=json AUTH_PROVIDER=local AUTH_REQUIRE_EMAIL_VERIFICATION=false
  RATE_LIMIT_READ_PER_MIN=3000
)

log "administrator"
setup="$(env "${api_env[@]}" DATABASE_URL="$DATABASE_URL" "$BIN_DIR/bootstrap-admin" -print-secrets \
  -email=console-e2e-admin@openctem-test.local -no-backup \
  -org-name='Console E2E Org' -org-slug=console-e2e -org-owner-email=console-e2e-owner@openctem-test.local 2>&1)" || { echo "$setup" >&2; exit 1; }
# The temporary password is printed once; the suite changes it on first sign-in.
TEMP_PASSWORD="$(sed -n 's/^ *Password: *\([^ ]*\).*/\1/p' <<<"$setup" | head -1)"
[[ -n "$TEMP_PASSWORD" ]] || { log "no temporary password in the bootstrap-admin output"; echo "$setup" >&2; exit 1; }
[[ -n "${GITHUB_ENV:-}" ]] && echo "::add-mask::$TEMP_PASSWORD"

log "API"
env "${api_env[@]}" "$BIN_DIR/server" >"$STACK_DIR/api.log" 2>&1 &
echo $! >>"$STACK_DIR/pids"

log "console"
(
  cd "$root/web"
  ADMIN_API_URL="http://127.0.0.1:${ADMIN_PORT}" BACKEND_API_URL="http://127.0.0.1:${API_PORT}" \
    SECURE_COOKIES=false NODE_ENV=production \
    exec npx next start console --hostname 127.0.0.1 --port "$CONSOLE_PORT"
) >"$STACK_DIR/console.log" 2>&1 &
echo $! >>"$STACK_DIR/pids"

for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:${ADMIN_PORT}/health" >/dev/null 2>&1 && curl -fsS -o /dev/null "$CONSOLE_URL/login"; then ready=1; break; fi
  sleep 2
done
[[ "${ready:-}" == 1 ]] || { log "the stack did not become ready"; tail -n 30 "$STACK_DIR"/*.log >&2; exit 1; }

umask 077
cat >"$STACK_DIR/env" <<ENV
CONSOLE_E2E_BASE_URL=$CONSOLE_URL
CONSOLE_E2E_EMAIL=console-e2e-admin@openctem-test.local
CONSOLE_E2E_PASSWORD=$TEMP_PASSWORD
ENV
[[ -n "${GITHUB_ENV:-}" ]] && cat "$STACK_DIR/env" >>"$GITHUB_ENV"
log "ready: $CONSOLE_URL (variables in $STACK_DIR/env)"
