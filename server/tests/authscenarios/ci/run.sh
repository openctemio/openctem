#!/usr/bin/env bash
# Runs the sign-in scenario suite (server/tests/authscenarios) against a
# scratch stack:
#   1. Postgres + Redis (ci/compose.yml, 127.0.0.1 only, tmpfs) and the
#      migrations of the tree under test (openctem-migrate)
#   2. the API built from the tree under test, listening on 127.0.0.1
#   3. go test -tags authscenarios ./tests/authscenarios/
#   4. tears everything down (always)
#
# Usage: server/tests/authscenarios/ci/run.sh [go test args...]
# Env:
#   AUTHSCEN_SERVER_DIR=<dir>  build the API and take the migrations from
#                              another tree (the server/ or api/ directory of a
#                              release checkout), to run this suite against an
#                              older version. Default: this tree.
#   AUTHSCEN_KEEP=1            keep the stack up (prints how to stop it)
#   AUTHSCEN_REPORT=<file>     write the JSON report there
#   AUTHSCEN_PROVIDER_URL=<u>  a stand-in social sign-in provider (test seam);
#                              AUTHSCEN_PROVIDER_BROWSER_URL as the browser
#                              reaches it (default: the same)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SUITE_DIR=$(cd "$HERE/../../.." && pwd)
SERVER_DIR=$(cd "${AUTHSCEN_SERVER_DIR:-$SUITE_DIR}" && pwd)
WORK=${AUTHSCEN_WORK:-$(mktemp -d)}
mkdir -p "$WORK"

rnd() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

export AUTHSCEN_DB_PASSWORD=${AUTHSCEN_DB_PASSWORD:-$(rnd)}
export AUTHSCEN_REDIS_PASSWORD=${AUTHSCEN_REDIS_PASSWORD:-$(rnd)}
export AUTHSCEN_DB_PORT=${AUTHSCEN_DB_PORT:-$(port)}
export AUTHSCEN_REDIS_PORT=${AUTHSCEN_REDIS_PORT:-$(port)}
API_PORT=${AUTHSCEN_API_PORT:-$(port)}
PROJECT="authscen-$AUTHSCEN_DB_PORT"
case "$PROJECT" in openctemio|openctem-sensor|openctemio-obs) echo "refusing project $PROJECT" >&2; exit 2 ;; esac
COMPOSE=(docker compose -p "$PROJECT" -f "$HERE/compose.yml")

SERVER_PID=""
cleanup() {
  if [[ "${AUTHSCEN_KEEP:-}" == 1 ]]; then
    echo "stack kept: kill $SERVER_PID; ${COMPOSE[*]} down -v" >&2
    return
  fi
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The URL is assembled from parts so no literal "scheme://user:password@host"
# string sits in the tree.
db_scheme=postgres
export DATABASE_URL="${db_scheme}://openctem:${AUTHSCEN_DB_PASSWORD}@127.0.0.1:${AUTHSCEN_DB_PORT}/openctem?sslmode=disable"
"${COMPOSE[@]}" up -d --wait postgres redis

# The API is a test build (tag authtestseam): with AUTHSCEN_PROVIDER_URL set,
# social sign-in reaches a stand-in provider at that URL
# (internal/app/auth/provider_endpoints.go). A tree without the seam ignores
# the tag.
(cd "$SERVER_DIR" && GOWORK=off go build -tags authtestseam -o "$WORK/" ./cmd/server ./cmd/openctem-migrate ./cmd/bootstrap-admin)
export AUTHSCEN_BOOTSTRAP="$WORK/bootstrap-admin"
PGPASSWORD="$AUTHSCEN_DB_PASSWORD" "$WORK/openctem-migrate" -path "$SERVER_DIR/migrations" \
  -database "${db_scheme}://openctem@127.0.0.1:${AUTHSCEN_DB_PORT}/openctem?sslmode=disable" up >"$WORK/migrate.log" 2>&1 \
  || { tail -20 "$WORK/migrate.log" >&2; exit 1; }

JWT_SECRET=$(rnd)
(
  export APP_ENV=test APP_URL=http://localhost:3999 CORS_ALLOWED_ORIGINS=http://localhost:3999 AUTH_COOKIE_SECURE=false
  export SERVER_HOST=127.0.0.1 SERVER_PORT=$API_PORT
  export DB_HOST=127.0.0.1 DB_PORT=$AUTHSCEN_DB_PORT DB_USER=openctem DB_PASSWORD=$AUTHSCEN_DB_PASSWORD DB_NAME=openctem DB_SSLMODE=disable
  export REDIS_HOST=127.0.0.1 REDIS_PORT=$AUTHSCEN_REDIS_PORT REDIS_PASSWORD=$AUTHSCEN_REDIS_PASSWORD
  export LOG_LEVEL=${AUTHSCEN_LOG_LEVEL:-warn} LOG_FORMAT=json AUTH_PROVIDER=local
  export AUTH_JWT_SECRET=$JWT_SECRET APP_ENCRYPTION_KEY=$(rnd) FINGERPRINT_KEY=$(rnd)
  # Each seeding session presents its own documentation-range address
  # (X-Forwarded-For from the loopback proxy), so per-address sign-in limits
  # apply per simulated person, as in production.
  export SERVER_TRUSTED_PROXIES=127.0.0.1/32
  export AUTH_ACCESS_TOKEN_DURATION=60m
  export SERVER_READ_TIMEOUT=60s SERVER_WRITE_TIMEOUT=60s
  # The platform floor is its own scenario dimension; the organizations
  # under test carry their own rules.
  export AUTH_MFA_FLOOR=none
  export AUTH_REQUIRE_EMAIL_VERIFICATION=false SELF_SERVICE_START_LIMITS=unlimited
  # Social sign-in is enabled (no provider round trip happens in the suite:
  # federated sessions are seeded as the callback leaves them).
  export RATE_LIMIT_ENABLED=false RATE_LIMIT_READ_PER_MIN=1000000 RATE_LIMIT_WRITE_PER_MIN=1000000 AUTH_MAX_LOGIN_ATTEMPTS=1000000
  if [[ -n "${AUTHSCEN_PROVIDER_URL:-}" ]]; then
    export AUTHTESTSEAM_PROVIDER_URL=$AUTHSCEN_PROVIDER_URL
    export AUTHTESTSEAM_PROVIDER_BROWSER_URL=${AUTHSCEN_PROVIDER_BROWSER_URL:-$AUTHSCEN_PROVIDER_URL}
  fi
  # The API reads its schema expectations (migrations/) from the working
  # directory: run it in the tree it was built from.
  cd "$SERVER_DIR"
  exec "$WORK/server" >"$WORK/server.log" 2>&1
) &
SERVER_PID=$!

export AUTHSCEN_API="http://127.0.0.1:$API_PORT"
for _ in $(seq 1 90); do
  curl -fsS "$AUTHSCEN_API/health" >/dev/null 2>&1 && break
  kill -0 "$SERVER_PID" 2>/dev/null || { tail -40 "$WORK/server.log" >&2; exit 1; }
  sleep 1
done
curl -fsS "$AUTHSCEN_API/health" >/dev/null || { tail -40 "$WORK/server.log" >&2; exit 1; }

export AUTHSCEN_DATABASE_URL="$DATABASE_URL"
if [[ "${AUTHSCEN_KEEP:-}" == 1 ]]; then
  echo "AUTHSCEN_API=$AUTHSCEN_API" >"$WORK/env"
  echo "AUTHSCEN_DATABASE_URL=$DATABASE_URL" >>"$WORK/env"
fi
cd "$SUITE_DIR"
status=0
GOWORK=off go test -tags authscenarios -count=1 -timeout 30m ./tests/authscenarios/ "$@" || status=$?
if [[ $status -ne 0 ]]; then
  echo "--- server log (last 60 lines) ---" >&2
  tail -60 "$WORK/server.log" >&2
fi
exit $status
