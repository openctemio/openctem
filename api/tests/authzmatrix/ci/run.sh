#!/usr/bin/env bash
# Runs the authorization matrix against a scratch stack:
#   1. Postgres + Redis (ci/compose.yml, 127.0.0.1 only, tmpfs) and migrations
#   2. the API built from this tree, listening on 127.0.0.1
#   3. go test -tags authzmatrix ./tests/authzmatrix/
#   4. tears everything down (always)
#
# Usage: api/tests/authzmatrix/ci/run.sh [go test args...]
# Env: MATRIX_KEEP=1 keeps the stack up (prints how to stop it),
#      MATRIX_REPORT=<file> writes the JSON report there.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
API_DIR=$(cd "$HERE/../../.." && pwd)
WORK=${MATRIX_WORK:-$(mktemp -d)}
mkdir -p "$WORK"

rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

export MATRIX_DB_PASSWORD=${MATRIX_DB_PASSWORD:-$(rnd)}
export MATRIX_REDIS_PASSWORD=${MATRIX_REDIS_PASSWORD:-$(rnd)}
export MATRIX_DB_PORT=${MATRIX_DB_PORT:-$(port)}
export MATRIX_REDIS_PORT=${MATRIX_REDIS_PORT:-$(port)}
API_PORT=${MATRIX_API_PORT:-$(port)}
PROJECT="authzmatrix-$MATRIX_DB_PORT"
case "$PROJECT" in openctemio|openctem-sensor|openctemio-obs) echo "refusing project $PROJECT" >&2; exit 2 ;; esac
COMPOSE=(docker compose -p "$PROJECT" -f "$HERE/compose.yml")

SERVER_PID=""
cleanup() {
  if [[ "${MATRIX_KEEP:-}" == 1 ]]; then
    echo "stack kept: kill $SERVER_PID; ${COMPOSE[*]} down -v" >&2
    return
  fi
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --wait postgres redis
"${COMPOSE[@]}" run --rm migrate >/dev/null 2>&1 || { "${COMPOSE[@]}" run --rm migrate; exit 1; }

(cd "$API_DIR" && GOWORK=off go build -o "$WORK/server" ./cmd/server)

export DATABASE_URL="postgres://openctem:$MATRIX_DB_PASSWORD@127.0.0.1:$MATRIX_DB_PORT/openctem?sslmode=disable"
(
  export APP_ENV=staging APP_URL=http://localhost:3999 CORS_ALLOWED_ORIGINS=http://localhost:3999 AUTH_COOKIE_SECURE=false
  export SERVER_HOST=127.0.0.1 SERVER_PORT=$API_PORT
  export DB_HOST=127.0.0.1 DB_PORT=$MATRIX_DB_PORT DB_USER=openctem DB_PASSWORD=$MATRIX_DB_PASSWORD DB_NAME=openctem DB_SSLMODE=disable
  export REDIS_HOST=127.0.0.1 REDIS_PORT=$MATRIX_REDIS_PORT REDIS_PASSWORD=$MATRIX_REDIS_PASSWORD
  export LOG_LEVEL=${MATRIX_LOG_LEVEL:-warn} LOG_FORMAT=json AUTH_PROVIDER=local
  export AUTH_JWT_SECRET=$(rnd) APP_ENCRYPTION_KEY=$(rnd) FINGERPRINT_KEY=$(rnd)
  export SERVER_TRUSTED_PROXIES=127.0.0.1/32
  # The suite runs longer than one access token lives; it signs in again
  # after 10 minutes, the longer lifetime is slack for a slow runner.
  export AUTH_ACCESS_TOKEN_DURATION=${MATRIX_TOKEN_TTL:-60m}
  # Password hashing on a busy runner can pass the default 15 s write
  # timeout; the connection would close before the answer.
  export SERVER_READ_TIMEOUT=60s SERVER_WRITE_TIMEOUT=60s
  export AUTH_REQUIRE_EMAIL_VERIFICATION=false SELF_SERVICE_START_LIMITS=unlimited
  # The matrix sends thousands of requests from a handful of accounts.
  export RATE_LIMIT_ENABLED=false RATE_LIMIT_READ_PER_MIN=1000000 RATE_LIMIT_WRITE_PER_MIN=1000000 AUTH_MAX_LOGIN_ATTEMPTS=1000000
  exec "$WORK/server" >"$WORK/server.log" 2>&1
) &
SERVER_PID=$!

export MATRIX_API="http://127.0.0.1:$API_PORT"
for _ in $(seq 1 90); do
  curl -fsS "$MATRIX_API/health" >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || { tail -40 "$WORK/server.log" >&2; exit 1; }
  sleep 1
done
curl -fsS "$MATRIX_API/health" >/dev/null || { tail -40 "$WORK/server.log" >&2; exit 1; }

export MATRIX_DATABASE_URL="$DATABASE_URL" MATRIX_API_ROOT="$API_DIR"
cd "$API_DIR"
status=0
GOWORK=off go test -tags authzmatrix -count=1 -timeout 60m ./tests/authzmatrix/ "$@" || status=$?
if [[ $status -ne 0 ]]; then
  echo "--- server log (last 60 lines) ---" >&2
  tail -60 "$WORK/server.log" >&2
fi
exit $status
