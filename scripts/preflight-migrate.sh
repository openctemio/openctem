#!/usr/bin/env bash
#
# preflight-migrate.sh — run data pre-flight checks, then migrate only if clean.
#
# Most migrations are pure schema and apply safely. A few in the 167–176 batch
# add a constraint/index that VALIDATES EXISTING DATA and will fail an upgrade
# mid-flight if the data violates it. golang-migrate runs each migration in a
# transaction, so such a failure rolls back that step but leaves
# schema_migrations.dirty = true, requiring manual `migrate force` to recover.
#
# This script catches those data-violation risks BEFORE touching the schema, so a
# deploy either proceeds cleanly or stops with an actionable message — never
# half-applied. It is safe to run repeatedly.
#
# Checks (skipped automatically if the relation is not present yet):
#   000170  asset_dedup_review — at most one PENDING review per (tenant, keep asset)
#           (a new partial UNIQUE index; duplicates would fail the build)
#   000171  findings.pentest_campaign_id — must reference an existing campaign
#           (a new FK; dangling references would fail validation)
#
# NOT data risks (no pre-flight needed): 000168 is a strict SUPERSET of the old
# CHECK (no existing row can violate it); 169/172/174 only redefine functions;
# 173/175/176 create new tables. The remaining concern for 000167/000171 on large
# tables is LOCK DURATION (CREATE INDEX / ADD FK on findings), not data — run them
# in a maintenance window. See docs/architecture/scan-coverage.md / migrations.
#
# Usage:
#   DATABASE_URL=postgres://user:pass@host:port/db?sslmode=disable \
#     ./scripts/preflight-migrate.sh [--check-only]
set -euo pipefail

MIGRATIONS_DIR="$(cd "$(dirname "$0")/.." && pwd)/migrations"
: "${DATABASE_URL:?set DATABASE_URL, e.g. postgres://user:pass@host:5432/db?sslmode=disable}"

CHECK_ONLY=0
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

command -v psql >/dev/null 2>&1 || { echo "ERROR: psql is required for pre-flight checks" >&2; exit 2; }

psql_val() { psql "$DATABASE_URL" -tAc "$1"; }

# relation_exists <regclass> -> "true"/"false"
relation_exists() { psql_val "SELECT (to_regclass('$1') IS NOT NULL)::text"; }
# column_exists <table> <column> -> "true"/"false"
column_exists() {
  psql_val "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='$1' AND column_name='$2')::text"
}

fail=0
report() { # name, count, why
  if [[ "$2" == "0" ]]; then
    echo "  ✓ $1: clean"
  else
    echo "  ✗ $1: $2 offending row(s) — $3" >&2
    fail=1
  fi
}

echo "== Pre-flight data checks =="

# 000170 — duplicate PENDING dedup reviews.
if [[ "$(relation_exists public.asset_dedup_review)" == "true" ]]; then
  n="$(psql_val "SELECT COALESCE(SUM(c-1),0) FROM (
         SELECT count(*) c FROM asset_dedup_review
         WHERE status='pending' GROUP BY tenant_id, keep_asset_id HAVING count(*)>1
       ) t" | tr -d '[:space:]')"
  report "000170 dedup-pending-unique" "${n:-0}" \
    "resolve/merge the duplicate PENDING reviews before migrating (the new UNIQUE index would fail)"
else
  echo "  – 000170 dedup-pending-unique: n/a (asset_dedup_review not present yet)"
fi

# 000171 — findings referencing a missing pentest campaign.
if [[ "$(relation_exists public.findings)" == "true" && "$(relation_exists public.pentest_campaigns)" == "true" \
      && "$(column_exists findings pentest_campaign_id)" == "true" ]]; then
  n="$(psql_val "SELECT count(*) FROM findings f
         WHERE f.pentest_campaign_id IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM pentest_campaigns c WHERE c.id = f.pentest_campaign_id)" | tr -d '[:space:]')"
  report "000171 pentest-campaign-fk" "${n:-0}" \
    "findings point at a missing pentest campaign; null them or delete before migrating (the new FK would fail)"
else
  echo "  – 000171 pentest-campaign-fk: n/a (findings/pentest_campaigns not present yet)"
fi

if [[ $fail -ne 0 ]]; then
  echo "Pre-flight FAILED — fix the rows above; NOT running migrate (schema untouched)." >&2
  exit 1
fi
echo "All pre-flight checks passed."

if [[ $CHECK_ONLY -eq 1 ]]; then
  echo "(--check-only: not running migrate)"
  exit 0
fi

command -v migrate >/dev/null 2>&1 || { echo "ERROR: 'migrate' (golang-migrate) is required to apply migrations" >&2; exit 2; }
echo "== Applying migrations =="
migrate -path "$MIGRATIONS_DIR" -database "$DATABASE_URL" up
echo "== Current version =="
migrate -path "$MIGRATIONS_DIR" -database "$DATABASE_URL" version
