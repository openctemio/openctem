#!/usr/bin/env bash
# upgrade-test.sh: the previous release's database, upgraded to this tree.
#
#   upgrade-test.sh [--prev vX.Y.Z] [--server-bin PATH]
#   upgrade-test.sh --print-prev-tag      the release it would start from
#
# What an operator does on upgrade day, on a scratch database:
#   1. bootstrap the roles and apply the PREVIOUS release's migrations as the
#      migrator (the schema owner, not a superuser): the database an install of
#      that release has;
#   2. load representative rows (api/scripts/upgrade-test/seed.sql);
#   3. apply THIS tree's migrations, re-run the roles script;
#   4. assert: the version is this tree's highest migration and not dirty, the
#      schema_migrations row is single, no key table lost a row, and, when
#      --server-bin is given, the API built from this tree starts against the
#      upgraded database as the app role and answers /health and /ready.
#
# Environment (the CI job sets them; defaults suit a local scratch server):
#   SUPER_URL      superuser connection to the scratch database
#   MIGRATOR_URL   migrator role connection (owns the schema)
#   APP_ROLE_URL   app role connection (DML only)
#   REDIS_HOST, REDIS_PORT   for the API boot (default localhost:6379)
#   API_PORT       port for the API boot (default 18080)
#
# Run from the repository root with `migrate` (golang-migrate) and `psql` on
# the PATH. The database must be empty: the script refuses to touch one that
# already has a schema_migrations table.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PREV=""
SERVER_BIN=""
PRINT_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --prev) PREV="$2"; shift ;;
    --server-bin) SERVER_BIN="$2"; shift ;;
    --print-prev-tag) PRINT_ONLY=true ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# The newest release tag reachable from HEAD, other than a tag that points at
# HEAD itself (a run on a release commit upgrades from the one before it).
prev_tag() {
  local here
  here="$(git tag --points-at HEAD --list 'v[0-9]*')"
  # grep exits 1 when there is no tag at all; that is the error reported below.
  git tag --merged HEAD --list 'v[0-9]*' --sort=-v:refname | { grep -vxF "${here:-__none__}" || true; } | head -n 1
}

if [ -z "$PREV" ]; then PREV="$(prev_tag)"; fi
if [ "$PRINT_ONLY" = true ]; then echo "$PREV"; exit 0; fi
[ -n "$PREV" ] || { echo "::error::no previous release tag is reachable from HEAD (fetch tags: fetch-depth 0)"; exit 1; }
git rev-parse --verify --quiet "refs/tags/$PREV" >/dev/null || { echo "::error::$PREV is not a tag here"; exit 1; }

: "${SUPER_URL:?SUPER_URL is required}"
: "${MIGRATOR_URL:?MIGRATOR_URL is required}"
: "${APP_ROLE_URL:?APP_ROLE_URL is required}"

psql_super() { psql "$SUPER_URL" -X -v ON_ERROR_STOP=1 "$@"; }
fail() { echo "::error::upgrade test: $*"; exit 1; }

work="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# max_version <migrations dir>: the highest NNN of the *.up.sql files.
max_version() {
  find "$1" -maxdepth 1 -name '*.up.sql' -printf '%f\n' | sed 's/_.*//' | sort -n | tail -n 1 | sed 's/^0*//'
}

if [ "$(psql_super -At -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL")" = t ]; then
  fail "the database already has a schema; it must be empty"
fi

echo "== Previous release: $PREV ($(git rev-parse --short "$PREV"))"
mkdir -p "$work/prev"
git archive "$PREV" api/migrations api/deploy/postgres 2>/dev/null | tar -x -C "$work/prev" || true
prev_migrations="$work/prev/api/migrations"
[ -d "$prev_migrations" ] || fail "$PREV has no api/migrations"
prev_roles="$work/prev/api/deploy/postgres/least-privilege-roles.sql"
[ -f "$prev_roles" ] || prev_roles="api/deploy/postgres/least-privilege-roles.sql" # a release older than the roles script
prev_max="$(max_version "$prev_migrations")"
new_max="$(max_version api/migrations)"
echo "   its migrations end at $prev_max; this tree's end at $new_max"
[ "$new_max" -ge "$prev_max" ] || fail "this tree's highest migration ($new_max) is below $PREV's ($prev_max)"

echo "== 1. The previous release's database"
psql_super -q -f "$prev_roles"
migrate -path "$prev_migrations" -database "$MIGRATOR_URL" up
psql_super -q -f "$prev_roles"
state="$(psql_super -At -F ' ' -c "SELECT version, dirty FROM schema_migrations")"
[ "$state" = "$prev_max f" ] || fail "after $PREV's migrations schema_migrations says '$state', want '$prev_max f'"
echo "   version $prev_max, not dirty"

echo "== 2. Representative rows"
psql_super -q -f api/scripts/upgrade-test/seed.sql

# key_counts: one "table count" line per key table, in a fixed order.
key_tables=(tenants users tenant_members user_roles assets findings sensors audit_logs roles permissions)
key_counts() {
  local t
  for t in "${key_tables[@]}"; do
    printf '%s %s\n' "$t" "$(psql_super -At -c "SELECT count(*) FROM public.${t}")"
  done
}
key_counts >"$work/before.txt"
sed 's/^/   /' "$work/before.txt"
awk '$1 == "findings" && $2 < 200 { bad = 1 } END { exit bad }' "$work/before.txt" || fail "the seed did not load (findings < 200)"

echo "== 3. This tree's migrations"
start=$(date +%s)
migrate -path api/migrations -database "$MIGRATOR_URL" up
echo "   applied in $(( $(date +%s) - start )) s"
psql_super -q -f api/deploy/postgres/least-privilege-roles.sql

echo "== 4. Assertions"
state="$(psql_super -At -F ' ' -c "SELECT version, dirty FROM schema_migrations")"
[ "$state" = "$new_max f" ] || fail "after the upgrade schema_migrations says '$state', want '$new_max f'"
echo "   version $new_max, not dirty"
rows="$(psql_super -At -c "SELECT count(*) FROM schema_migrations")"
[ "$rows" = 1 ] || fail "schema_migrations has $rows rows, want 1"

key_counts >"$work/after.txt"
lost=0
while read -r table before; do
  after="$(awk -v t="$table" '$1 == t { print $2 }' "$work/after.txt")"
  if [ "$after" -lt "$before" ]; then
    echo "::error::upgrade test: table $table went from $before rows to $after"
    lost=1
  else
    echo "   $table: $before -> $after rows"
  fi
done <"$work/before.txt"
[ "$lost" = 0 ] || exit 1

# The app role must still reach the data the migrations just rewrote.
psql "$APP_ROLE_URL" -X -v ON_ERROR_STOP=1 -At -c "SELECT count(*) FROM findings" >/dev/null \
  || fail "the app role cannot read findings after the upgrade"
echo "   the app role reads the upgraded data"

if [ -n "$SERVER_BIN" ]; then
  echo "== 5. The API starts against the upgraded database"
  url="${APP_ROLE_URL#*://}"      # user@host:port/db?params
  creds="${url%%@*}"
  hostpart="${url#*@}"
  hostport="${hostpart%%/*}"
  dbname="${hostpart#*/}"; dbname="${dbname%%\?*}"
  port="${API_PORT:-18080}"
  rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
  APP_ENV=development AUTH_PROVIDER=local AUTH_REQUIRE_EMAIL_VERIFICATION=false \
    AUTH_JWT_SECRET="$(rand)" APP_ENCRYPTION_KEY="$(rand)" FINGERPRINT_KEY="$(rand)" \
    DB_HOST="${hostport%%:*}" DB_PORT="${hostport##*:}" DB_USER="${creds%%:*}" DB_NAME="$dbname" DB_SSLMODE=disable \
    REDIS_HOST="${REDIS_HOST:-localhost}" REDIS_PORT="${REDIS_PORT:-6379}" SERVER_PORT="$port" \
    "$SERVER_BIN" >"$work/server.log" 2>&1 &
  server_pid=$!
  ok=false
  for _ in $(seq 1 60); do
    if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
    if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then ok=true; break; fi
    sleep 1
  done
  if [ "$ok" != true ]; then
    tail -n 60 "$work/server.log" || true
    fail "the API did not answer /health against the upgraded database"
  fi
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/ready")"
  if [ "$code" != 200 ]; then
    tail -n 60 "$work/server.log" || true
    fail "/ready answered $code, want 200"
  fi
  echo "   /health and /ready answer 200"
fi

echo "upgrade test passed: $PREV ($prev_max) -> $(git rev-parse --short HEAD) ($new_max)"
