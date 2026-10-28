#!/usr/bin/env bash
# migration-order-check.sh <base-commit>
#
# Proves that the order in which databases receive this tree's migrations
# does not change the schema (docs/rfcs/RFC-130-migration-applied-set.md).
# openctem-migrate applies every migration a database has not applied, so a
# migration merged after a higher-numbered one runs AFTER it on a database
# that is already at the base, but BEFORE it on a fresh install. Both must
# end with the same schema:
#
#   fresh    a new database, this tree's migrations, in version order;
#   upgrade  a new database, the base commit's migrations, then this tree's
#            (the database every running install has).
#
# The two schema fingerprints (.github/scripts/schema-fingerprint.sql) must
# be equal; a difference fails with the diff. The upgrade must also have
# applied every migration of the tree (`status` shows none pending).
#
# Environment: SUPER_URL, a connection with CREATEDB to the scratch server
# (postgres://user@host:port/db?...). openctem-migrate and psql on the PATH.
# MIGRATION_ORDER_BASE_DIR replaces the base commit's migrations with a
# directory (tests). Run from the repository root.
set -euo pipefail

base="${1:?usage: migration-order-check.sh <base-commit>}"
dir=api/migrations
: "${SUPER_URL:?SUPER_URL is required}"

work="$(mktemp -d)"
base_dir="${MIGRATION_ORDER_BASE_DIR:-}"
if [[ -z "$base_dir" ]]; then
  if git diff --quiet "$base" HEAD -- "$dir/"; then
    echo "migration-order-check: no migration changed against $base; nothing to compare"
    exit 0
  fi
  mkdir -p "$work/base"
  git archive "$base" "$dir" | tar -x -C "$work/base"
  base_dir="$work/base/$dir"
fi

# url_for <db>: SUPER_URL pointed at another database of the same server.
url_for() {
  local u="${SUPER_URL%%\?*}" q=""
  [[ "$SUPER_URL" == *\?* ]] && q="?${SUPER_URL#*\?}"
  echo "${u%/*}/$1$q"
}
suffix="$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
fresh="mo_fresh_${suffix}" upgrade="mo_upgrade_${suffix}"
cleanup() {
  psql "$SUPER_URL" -X -q -c "DROP DATABASE IF EXISTS ${fresh} WITH (FORCE)" -c "DROP DATABASE IF EXISTS ${upgrade} WITH (FORCE)" >/dev/null 2>&1 || true
}
trap cleanup EXIT
psql "$SUPER_URL" -X -q -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${fresh}" -c "CREATE DATABASE ${upgrade}"

echo "::group::fresh: this tree's migrations"
openctem-migrate -path "$dir" -database "$(url_for "$fresh")" up | tail -n 3
echo "::endgroup::"
echo "::group::upgrade: the base's migrations, then this tree's"
openctem-migrate -path "$base_dir" -database "$(url_for "$upgrade")" up | tail -n 3
openctem-migrate -path "$dir" -database "$(url_for "$upgrade")" up
echo "::endgroup::"

pending="$(openctem-migrate -path "$dir" -database "$(url_for "$upgrade")" status | sed -n 's/^pending: //p')"
if [[ "$pending" != 0 ]]; then
  echo "::error::the upgraded database still has $pending pending migrations"
  exit 1
fi

fp() { psql "$(url_for "$1")" -X -At -v ON_ERROR_STOP=1 -f .github/scripts/schema-fingerprint.sql; }
fp "$fresh" >"$work/fresh.txt"
fp "$upgrade" >"$work/upgrade.txt"
if ! diff -u "$work/fresh.txt" "$work/upgrade.txt" >"$work/diff.txt"; then
  echo "::error::the schema depends on the order the migrations are applied in: a fresh install and an upgraded database differ (- fresh, + upgrade). Make the migrations independent of each other's order (or give the later one a version above the one it depends on)."
  head -n 80 "$work/diff.txt"
  exit 1
fi
echo "migration-order-check: fresh and upgraded schemas are identical ($(wc -l <"$work/fresh.txt") objects)"
