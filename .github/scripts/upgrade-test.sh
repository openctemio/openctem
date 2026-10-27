#!/usr/bin/env bash
# upgrade-test.sh: the previous release's database, upgraded to this tree.
#
#   upgrade-test.sh [--prev vX.Y.Z] [--server-bin PATH]
#   upgrade-test.sh --print-prev-tag      the release it would start from
#   upgrade-test.sh --check-order [--prev vX.Y.Z]   only the migration-order check (no database)
#
# What an operator does on upgrade day, on a scratch database:
#   1. bootstrap the roles and apply the PREVIOUS release's migrations as the
#      migrator (the schema owner, not a superuser): the database an install of
#      that release has;
#   2. load representative rows (api/scripts/upgrade-test/seed.sql);
#   3. apply THIS tree's migrations with this tree's openctem-migrate, re-run
#      the roles script;
#   0. (before any database work) refuse a legacy-numbered migration of this
#      tree at or below the previous release's highest that the release does
#      not have: when openctem-migrate takes over a database the earlier tool
#      migrated, it records every legacy-numbered file up to that tool's
#      version as applied (docs/rfcs/RFC-130-migration-applied-set.md), so
#      such a file would never run. Timestamp versions are exempt;
#   4. assert: nothing is pending, schema_migrations holds the runner's fence
#      and is not dirty, no key table lost a row, the upgraded schema equals a
#      fresh install of this tree (.github/scripts/schema-fingerprint.sql),
#      and, when --server-bin is given, the API built from this tree starts
#      against the upgraded database as the app role and answers /health and
#      /ready.
#
# Environment (the CI job sets them; defaults suit a local scratch server):
#   SUPER_URL      superuser connection to the scratch database
#   MIGRATOR_URL   migrator role connection (owns the schema)
#   APP_ROLE_URL   app role connection (DML only)
#   REDIS_HOST, REDIS_PORT   for the API boot (default localhost:6379)
#   API_PORT       port for the API boot (default 18080)
#
# Run from the repository root with `openctem-migrate` (this tree's) and
# `psql` on the PATH, and `migrate` (golang-migrate) when the previous release
# predates openctem-migrate. The database must be empty: the script refuses to
# touch one that already has a schema_migrations table.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PREV=""
SERVER_BIN=""
PRINT_ONLY=false
CHECK_ORDER_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --prev) PREV="$2"; shift ;;
    --server-bin) SERVER_BIN="$2"; shift ;;
    --print-prev-tag) PRINT_ONLY=true ;;
    --check-order) CHECK_ORDER_ONLY=true ;;
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

if [ "$CHECK_ORDER_ONLY" != true ]; then
  : "${SUPER_URL:?SUPER_URL is required}"
  : "${MIGRATOR_URL:?MIGRATOR_URL is required}"
  : "${APP_ROLE_URL:?APP_ROLE_URL is required}"
fi

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

echo "== Previous release: $PREV ($(git rev-parse --short "$PREV"))"
mkdir -p "$work/prev"
# One archive per path: `git archive` fails as a whole when one path is
# missing, and a release older than the roles script has no api/deploy/postgres.
for p in api/migrations api/deploy/postgres; do
  if git cat-file -e "$PREV:$p" 2>/dev/null; then git archive "$PREV" "$p" | tar -x -C "$work/prev"; fi
done
prev_migrations="$work/prev/api/migrations"
[ -d "$prev_migrations" ] || fail "$PREV has no api/migrations"
prev_roles="$work/prev/api/deploy/postgres/least-privilege-roles.sql"
[ -f "$prev_roles" ] || prev_roles="api/deploy/postgres/least-privilege-roles.sql" # a release older than the roles script
prev_max="$(max_version "$prev_migrations")"
new_max="$(max_version api/migrations)"
echo "   its migrations end at $prev_max; this tree's end at $new_max"
[ "$new_max" -ge "$prev_max" ] || fail "this tree's highest migration ($new_max) is below $PREV's ($prev_max)"

# 0. Legacy migration order. Every legacy-numbered (up to 13 digits) version
# of this tree at or below the previous release's highest must be one that
# release already has; anything else would be recorded as applied, never run,
# when openctem-migrate takes over an install of that release. Compared by
# version, not file name: a renamed released migration never runs again anyway.
versions() { find "$1" -maxdepth 1 -name '*.up.sql' -printf '%f\n' | sed 's/_.*//; s/^0*//; s/^$/0/' | awk 'length($0) < 14' | sort -n -u; }
versions "$prev_migrations" >"$work/prev-versions"
skipped=""
while IFS= read -r v; do
  if [ "$v" -le "$prev_max" ] && ! grep -qxF "$v" "$work/prev-versions"; then
    skipped="$skipped $(find api/migrations -maxdepth 1 -name "*.up.sql" -printf '%f\n' | awk -F_ -v v="$v" '$1 + 0 == v' | head -n 1)"
  fi
done < <(versions api/migrations)
if [ -n "$skipped" ]; then
  fail "legacy-numbered at or below $PREV's highest migration ($prev_max) but not in $PREV, so an upgrade would record them as applied without running them:$skipped (give them timestamp versions: make -C api migration-renumber)"
fi
echo "   no legacy-numbered migration of this tree would be skipped on upgrade"
if [ "$CHECK_ORDER_ONLY" = true ]; then exit 0; fi

if [ "$(psql_super -At -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL")" = t ]; then
  fail "the database already has a schema; it must be empty"
fi

# The previous release's own migration tool: its openctem-migrate, built from
# the tag, or golang-migrate for a release before it.
prev_migrate=migrate
if git cat-file -e "$PREV:api/cmd/openctem-migrate/main.go" 2>/dev/null; then
  mkdir -p "$work/prev-src"
  git archive "$PREV" api | tar -x -C "$work/prev-src"
  (cd "$work/prev-src/api" && GOWORK=off go build -o "$work/prev-migrate" ./cmd/openctem-migrate)
  prev_migrate="$work/prev-migrate"
fi

echo "== 1. The previous release's database"
psql_super -q -f "$prev_roles"
"$prev_migrate" -path "$prev_migrations" -database "$MIGRATOR_URL" up
psql_super -q -f "$prev_roles"
state="$(psql_super -At -F ' ' -c "SELECT version, dirty FROM schema_migrations")"
case "$state" in
  "$prev_max f" | "9223372036854775807 f") ;;
  *) fail "after $PREV's migrations schema_migrations says '$state', want '$prev_max f' (or the fence)" ;;
esac
echo "   migrated to $prev_max, not dirty"

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
openctem-migrate -path api/migrations -database "$MIGRATOR_URL" up | tail -n 5
echo "   applied in $(( $(date +%s) - start )) s"
psql_super -q -f api/deploy/postgres/least-privilege-roles.sql

echo "== 4. Assertions"
pending="$(openctem-migrate -path api/migrations -database "$MIGRATOR_URL" status | sed -n 's/^pending: //p')"
[ "$pending" = 0 ] || fail "after the upgrade $pending migrations are still pending"
state="$(psql_super -At -F ' ' -c "SELECT version, dirty FROM schema_migrations")"
[ "$state" = "9223372036854775807 f" ] || fail "after the upgrade schema_migrations says '$state', want the runner's fence, not dirty"
applied="$(psql_super -At -c "SELECT max(version) FROM schema_migrations_applied")"
[ "$applied" = "$new_max" ] || fail "the highest applied migration is '$applied', want $new_max"
echo "   nothing pending, highest applied $new_max, not dirty"

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

# The upgraded schema is a fresh install's: a database of its own, the roles
# script, this tree's migrations as the migrator, then the fingerprints.
url_db() { local u="${1%%\?*}" q=""; [[ "$1" == *\?* ]] && q="?${1#*\?}"; echo "${u%/*}/$2$q"; }
fresh_db="upgrade_fresh_$$"
psql_super -q -c "CREATE DATABASE ${fresh_db}"
psql "$(url_db "$SUPER_URL" "$fresh_db")" -X -q -v ON_ERROR_STOP=1 -f api/deploy/postgres/least-privilege-roles.sql
openctem-migrate -path api/migrations -database "$(url_db "$MIGRATOR_URL" "$fresh_db")" up | tail -n 1
psql_super -At -v ON_ERROR_STOP=1 -f .github/scripts/schema-fingerprint.sql >"$work/upgraded.fp"
psql "$(url_db "$SUPER_URL" "$fresh_db")" -X -At -v ON_ERROR_STOP=1 -f .github/scripts/schema-fingerprint.sql >"$work/fresh.fp"
psql_super -q -c "DROP DATABASE ${fresh_db} WITH (FORCE)"
if ! diff -u "$work/fresh.fp" "$work/upgraded.fp" >"$work/fp.diff"; then
  head -n 80 "$work/fp.diff"
  fail "the upgraded schema differs from a fresh install of this tree (- fresh, + upgraded)"
fi
echo "   the upgraded schema equals a fresh install ($(wc -l <"$work/fresh.fp") objects)"

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
