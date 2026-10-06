#!/usr/bin/env bash
# =============================================================================
# squash-migrations.sh — replace the migration chain with one baseline file and
# prove that a database built from it is the database the chain builds.
# Design: docs/rfcs/RFC-053-migration-baseline.md
#
# Usage (from anywhere; paths are resolved from this script):
#   scripts/squash-migrations.sh [REF]        generate, then verify
#   VERIFY_ONLY=1 scripts/squash-migrations.sh [REF]
#
# REF (default origin/develop) is the git ref whose api/migrations is squashed.
# V is the highest migration version at REF.
#
#   1. Apply REF's chain to a throwaway PostgreSQL 17 and pg_dump it into
#      migrations/<V>_baseline.up.sql (schema + built-in rows, no owners, no
#      grants: those come from deploy/postgres/least-privilege-roles.sql).
#      Tables in EXCLUDE_TABLES are left out; a migration above V must drop
#      them, or step 3 fails. Every work-tree migration <= V except the
#      baseline is removed (git rm).
#   2. (nothing else is touched: migrations above V stay as they are)
#   3. Verify, on fresh databases:
#        A = REF's chain + the work tree's migrations above V
#        B = the work tree's migrations (baseline + those above V)
#      both as the superuser and as the least-privilege migrator (bootstrap,
#      migrate, bootstrap again — what the CI job does). The schema dumps,
#      with owners and grants, must be byte-identical; the data dumps must be
#      identical once the values the migrations generate at run time
#      (now() timestamps, random/time-based UUIDs) are masked. The masking is
#      shown to be complete by also comparing two independent chain runs.
#
# Requires: docker, git, golang-migrate (`migrate` on PATH or MIGRATE=path).
# Exit: 0 = baseline written and identical, 1 = difference, 2 = environment.
# =============================================================================
set -euo pipefail

API="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(git -C "$API" rev-parse --show-toplevel)"
REF="${1:-origin/develop}"
MIGRATE="${MIGRATE:-migrate}"
PG_IMAGE="${PG_IMAGE:-postgres:17-alpine}"
EXCLUDE_TABLES="${EXCLUDE_TABLES:-priority_rule_safety_report role_permissions_admin_only_stripped}"
CONTAINER="openctem-squash-$$"
WORK="$(mktemp -d)"
OUT="${SQUASH_OUT:-$WORK/out}" # dumps and diffs are kept here for review
mkdir -p "$OUT"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK/chain" "$WORK/a" "$WORK/b"; }
trap cleanup EXIT
die() { echo "squash-migrations: $*" >&2; exit 2; }

command -v docker >/dev/null || die "docker is required"
command -v "$MIGRATE" >/dev/null || die "golang-migrate is required (set MIGRATE=/path/to/migrate)"
git -C "$REPO" rev-parse -q --verify "$REF^{commit}" >/dev/null || die "unknown ref $REF"
SHA="$(git -C "$REPO" rev-parse "$REF")"

# --- REF's chain ---------------------------------------------------------------
mkdir -p "$WORK/chain"
git -C "$REPO" archive "$SHA" api/migrations | tar -x -C "$WORK/chain"
CHAIN="$WORK/chain/api/migrations"
version_of() { local f="${1##*/}"; echo $((10#${f%%_*})); }
V=0
for f in "$CHAIN"/*.up.sql; do v="$(version_of "$f")"; ((v > V)) && V=$v; done
((V > 0)) || die "no migrations at $REF"
VV="$(printf '%06d' "$V")"
BASE_UP="$API/migrations/${VV}_baseline.up.sql"
BASE_DOWN="$API/migrations/${VV}_baseline.down.sql"
echo "squash-migrations: $REF ($SHA) has migrations up to $VV"

# --- throwaway PostgreSQL -------------------------------------------------------
docker run -d --name "$CONTAINER" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 \
  "$PG_IMAGE" -c fsync=off >/dev/null || die "cannot start $PG_IMAGE"
# initdb restarts the server once; two successful queries in a row mean the
# final server is up.
ok=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" psql -U postgres -qtAc 'SELECT 1' >/dev/null 2>&1; then
    ok=$((ok + 1)); ((ok >= 2)) && break
  else ok=0; fi
  sleep 1
done
((ok >= 2)) || die "postgres did not start"
PORT="$(docker port "$CONTAINER" 5432/tcp | head -1 | sed 's/.*://')"
url() { echo "postgres://$1@127.0.0.1:$PORT/$2?sslmode=disable"; }
sql() { docker exec -i "$CONTAINER" psql -U postgres -X -q -v ON_ERROR_STOP=1 "$@"; }
createdb() { sql -c "CREATE DATABASE $1" >/dev/null; }
bootstrap() { sql -d "$1" <"$API/deploy/postgres/least-privilege-roles.sql" >/dev/null; }
migrate_up() { "$MIGRATE" -path "$1" -database "$2" up >"$OUT/migrate-$3.log" 2>&1 || { cat "$OUT/migrate-$3.log" >&2; die "migrate failed ($3)"; }; }
pgdump() { docker exec "$CONTAINER" pg_dump -U postgres -d "$@" 2>>"$OUT/pg_dump.log" | sed -E '/^\\(un)?restrict /d; /^-- Dumped (from|by) /d'; }

# --- 1. generate -------------------------------------------------------------------
if [ "${VERIFY_ONLY:-0}" != 1 ]; then
  createdb gen
  migrate_up "$CHAIN" "$(url postgres gen)" gen
  excl=()
  for t in $EXCLUDE_TABLES; do excl+=("--exclude-table=public.$t"); done
  pgdump gen --no-owner --no-privileges --column-inserts --no-tablespaces --no-security-labels \
    --no-publications --no-subscriptions --exclude-table=public.schema_migrations "${excl[@]}" >"$WORK/gen.sql"

  {
    cat <<EOF
-- Migration baseline: the schema and built-in rows that migrations 000001-$VV
-- produced (docs/rfcs/RFC-053-migration-baseline.md). Generated by
-- scripts/squash-migrations.sh from commit $SHA; do not edit.
-- A schema change is a new migration numbered above this one.
--
-- A database already at version $VV or later never runs this file. One older
-- than $VV is refused by golang-migrate (its version has no file here): upgrade
-- it with a release from before the baseline (git tag pre-baseline-$VV) first.
--
-- No owners and no grants: objects belong to the role that runs this file (the
-- migrator), and deploy/postgres/least-privilege-roles.sql grants the app role.
--
-- expand-contract-ok: baseline for an empty database; it only creates objects
SET check_function_bodies = false;

DO \$baseline\$
BEGIN
    IF to_regclass('public.tenants') IS NOT NULL THEN
        RAISE EXCEPTION 'migration baseline $VV installs into an empty database only, and this one already has the OpenCTEM schema. Upgrade it with a release from before the baseline (git tag pre-baseline-$VV) first, see api/docs/development/migrations.md';
    END IF;
END
\$baseline\$;

EOF
    # The dump's header (everything before its first object) holds psql
    # session settings, which golang-migrate would leave on its pooled
    # connection: dropped. So is "SET default_table_access_method = heap;"
    # (the default). COMMENT ON EXTENSION needs the extension's owner and
    # repeats the comment CREATE EXTENSION sets: dropped with its "--" /
    # "-- Name:" / "--" header. Everything else is copied byte for byte (a
    # function body can contain any line, so nothing is squeezed or rewritten).
    awk '
      !body { if ($0 ~ /^-- Name: /) { body = 1; held = 1 } else next }
      $0 == "-- PostgreSQL database dump complete" { exit }
      skip { if ($0 ~ /^COMMENT ON EXTENSION /) skip = 0; next }
      held { held = 0; if ($0 ~ /^-- Name: EXTENSION .*; Type: COMMENT;/) { skip = 1; next } print "--" }
      $0 == "--" { held = 1; next }
      $0 == "SET default_table_access_method = heap;" { next }
      { print }
    ' "$WORK/gen.sql"
    echo "RESET check_function_bodies;"
  } >"$BASE_UP"

  cat >"$BASE_DOWN" <<EOF
-- The baseline is not reverted: there is no older schema in this tree to go
-- back to, and reverting it would drop every table. Restore a backup instead.
DO \$\$
BEGIN
    RAISE EXCEPTION 'migration baseline $VV cannot be reverted; restore a database backup instead';
END
\$\$;
EOF

  # Remove the squashed files from the work tree.
  for f in "$API"/migrations/*.sql; do
    v="$(version_of "$f")"
    if ((v <= V)) && [ "$f" != "$BASE_UP" ] && [ "$f" != "$BASE_DOWN" ]; then
      git -C "$REPO" rm -q --cached --ignore-unmatch "${f#"$REPO"/}"
      rm -f "$f"
    fi
  done
  git -C "$REPO" add "${BASE_UP#"$REPO"/}" "${BASE_DOWN#"$REPO"/}"
  echo "squash-migrations: wrote ${BASE_UP#"$REPO"/} ($(wc -l <"$BASE_UP") lines)"
fi

# --- 3. verify -----------------------------------------------------------------------
[ -f "$BASE_UP" ] || die "no baseline ${BASE_UP#"$REPO"/} to verify"
mkdir -p "$WORK/a" "$WORK/b"
cp "$CHAIN"/*.sql "$WORK/a/"
for f in "$API"/migrations/*.sql; do
  cp "$f" "$WORK/b/"
  (($(version_of "$f") > V)) && cp "$f" "$WORK/a/"
done

# Data: values the migrations compute when they run (now(), random and
# time-based UUIDs v4/v7) are masked, and pg_dump's "-- Data for Name:"
# comments are dropped (it orders those of empty tables arbitrarily); the
# INSERT and setval statements are compared in order.
mask() {
  sed -E -e '/^--/d; /^$/d' \
    -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(\+00(:00)?|Z)/<now>/g' \
    -e 's/[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/<uuid>/g'
}
# Schema: compared byte for byte except for one way PostgreSQL prints an
# expression differently after a dump and restore. `col IN ('a', 'b')` on a
# varchar column is stored as text = ANY of a varchar array cast to text[] and
# printed as ((ARRAY['a'::character varying, ...])::text[]); reading that text
# back casts each element instead, printed as
# (ARRAY[('a'::character varying)::text, ...]). Both mean the same check (a
# dump and restore of any such database shows it). The first form is
# rewritten to the second; nothing else is.
canon() {
  perl -pe 's{\(\(ARRAY\[((?:\x27(?:[^\x27]|\x27\x27)*\x27::character varying(?:, )?)+)\]\)::text\[\]\)}{
    "(ARRAY[" . join(", ", map { "($_)::text" } ($1 =~ /(\x27(?:[^\x27]|\x27\x27)*\x27::character varying)/g)) . "])"
  }ge'
}

fail=0
compare() { # name file1 file2
  if cmp -s "$2" "$3"; then
    echo "  identical: $1 ($(wc -l <"$2") lines)"
  else
    echo "  DIFFERENT: $1 (see $OUT/$1.diff)" >&2
    diff -u "$2" "$3" >"$OUT/$1.diff" || true
    head -40 "$OUT/$1.diff" >&2
    fail=1
  fi
}

for mode in super lp; do
  for side in a a2 b; do
    db="${mode}_${side}"
    createdb "$db"
    dir="$WORK/${side%2}"
    if [ "$mode" = super ]; then
      migrate_up "$dir" "$(url postgres "$db")" "$db"
    else
      bootstrap "$db"
      migrate_up "$dir" "$(url openctem_migrator "$db")" "$db"
      bootstrap "$db"
    fi
    pgdump "$db" --schema-only >"$OUT/$db.schema.raw.sql"
    canon <"$OUT/$db.schema.raw.sql" >"$OUT/$db.schema.sql"
    pgdump "$db" --data-only --column-inserts | mask >"$OUT/$db.data.sql"
  done
  echo "squash-migrations: $mode — chain vs baseline"
  for side in a b; do
    n="$(diff "$OUT/${mode}_$side.schema.raw.sql" "$OUT/${mode}_$side.schema.sql" | grep -c '^<' || true)"
    echo "  ($side: the IN-list rewrite changed $n lines)"
  done
  compare "$mode-schema" "$OUT/${mode}_a.schema.sql" "$OUT/${mode}_b.schema.sql"
  compare "$mode-data" "$OUT/${mode}_a.data.sql" "$OUT/${mode}_b.data.sql"
  echo "squash-migrations: $mode — chain vs chain (the masking hides only run-time values)"
  compare "$mode-data-chain" "$OUT/${mode}_a.data.sql" "$OUT/${mode}_a2.data.sql"
done
docker exec "$CONTAINER" pg_dumpall -U postgres --roles-only --no-role-passwords |
  sed -E '/^\\(un)?restrict /d; /^-- Dumped (from|by) /d' >"$OUT/roles.sql"

if ((fail)); then
  echo "squash-migrations: the baseline does NOT reproduce the chain (outputs in $OUT)" >&2
  exit 1
fi
echo "squash-migrations: baseline $VV reproduces the chain at $REF (outputs in $OUT)"
