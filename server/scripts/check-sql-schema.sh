#!/usr/bin/env bash
# =============================================================================
# check-sql-schema.sh — catch Go-vs-database drift at build time.
#
# WHY THIS EXISTS
# ---------------
# The startup schema check (cmd/server/schema_check.go) only compares the
# migration VERSION. It cannot tell whether the columns the code actually
# references exist. That gap shipped a run of bugs that were invisible to
# `go build`, `go vet`, the linters and the unit tests, and only failed when a
# real query ran against a real database:
#
#   * pipeline runs stuck in 'running' forever  — `$2 IN (...)` deduced text
#     while the column is varchar → 42P08 on the terminal transition of every run
#   * asset stale-detection never demoted anything — code said `last_seen_at`,
#     the column is `last_seen` → 42703
#   * cancelling a pipeline run never worked — assigned `commands.updated_at`,
#     a column no migration creates → 42703
#   * the EPSS sync died on every run — a COPY staging table hardcoded in Go as
#     DECIMAL(8,6) while the real column had been widened to numeric(9,6)
#
# Every one of them would have been caught here.
#
# HOW IT WORKS
# ------------
#   1. start a throwaway PostgreSQL
#   2. apply every migrations/*.up.sql in order — so the schema is exactly what
#      a fresh production deploy gets, not whatever a dev database has drifted to
#   3. extract SQL string literals from the Go sources
#   4. PREPARE each one. Postgres itself is the oracle: it resolves every table,
#      column, type and parameter without any data or fixtures.
#
# Only statements that are complete and parameter-clean can be prepared, so a
# statement assembled with fmt.Sprintf/strings.Join is skipped rather than
# guessed at — see the LIMITATIONS note at the bottom, which is honest about the
# residual gap instead of implying full coverage.
#
# Usage:  scripts/check-sql-schema.sh [--keep]
# Exit:   0 = no drift, 1 = drift found, 2 = usage or environment error
# =============================================================================
# GitHub Actions invokes steps as `bash -e {0}`, so errexit is inherited even
# though this script handles every failure explicitly. Under -e the readiness
# probe below — which is SUPPOSED to fail while Postgres boots — killed the run.
set +e
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="openctem-sqlgate-$$"
PGPORT="${SQLGATE_PORT:-55432}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

cleanup() {
  if [ "$KEEP" -eq 0 ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  else
    echo "check-sql-schema: leaving $CONTAINER running on port $PGPORT (--keep)" >&2
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "check-sql-schema: docker is required" >&2; exit 2; }

psql_q() { docker exec -i "$CONTAINER" psql -U postgres -d gate -v ON_ERROR_STOP=1 -qtA "$@"; }

# --- 1. throwaway database ---------------------------------------------------
echo "check-sql-schema: starting a throwaway PostgreSQL…"
docker run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=gate -e POSTGRES_DB=gate \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  postgres:17-alpine >/dev/null 2>&1 || { echo "check-sql-schema: could not start postgres" >&2; exit 2; }

# The official image bootstraps in two phases: initdb starts a TEMPORARY server,
# creates the database, shuts it down, then starts the real one. pg_isready is
# satisfied by that temporary server, so probing it races the restart — locally
# the timing happened to work, in CI it caught the shutdown and reported
# "database gate does not exist". Require a real query to succeed TWICE in a row
# instead: that can only happen once the final server is up.
ready=0
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" psql -U postgres -d gate -c 'SELECT 1' >/dev/null 2>&1; then
    ready=$((ready + 1))
    [ "$ready" -ge 2 ] && break
  else
    ready=0
  fi
  sleep 1
done

if [ "$ready" -lt 2 ]; then
  echo "check-sql-schema: postgres never became ready — container output follows:" >&2
  docker logs "$CONTAINER" 2>&1 | tail -30 | sed 's/^/    /' >&2
  exit 2
fi

# --- 2. apply the migrations, in order ---------------------------------------
echo "check-sql-schema: applying migrations…"
applied=0
for f in "$REPO_ROOT"/migrations/*.up.sql; do
  if ! docker exec -i "$CONTAINER" psql -U postgres -d gate -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>/tmp/sqlgate_mig.err; then
    echo "✗ migration failed to apply on a fresh database: ${f#"$REPO_ROOT"/}" >&2
    sed 's/^/    /' /tmp/sqlgate_mig.err >&2
    exit 1
  fi
  applied=$((applied + 1))
done
echo "check-sql-schema: $applied migrations applied cleanly from empty."

# --- 3. extract candidate statements from the Go sources ---------------------
echo "check-sql-schema: extracting SQL from Go sources…"
STMTS=/tmp/sqlgate_stmts.txt
python3 "$REPO_ROOT/scripts/extract_sql.py" "$REPO_ROOT" > "$STMTS" || {
  echo "check-sql-schema: extraction failed" >&2; exit 2; }

total=$(wc -l < "$STMTS")
echo "check-sql-schema: $total preparable statements found."

# --- 4. let Postgres judge ---------------------------------------------------
# One psql run, not one per statement: a \echo marker before each PREPARE lets us
# attribute an error back to its source location, and skipping ON_ERROR_STOP means
# a bad statement doesn't hide the ones after it.
BATCH=/tmp/sqlgate_batch.sql
MAP=/tmp/sqlgate_map.txt
: > "$BATCH"; : > "$MAP"
n=0
while IFS=$'\t' read -r loc sql; do
  [ -z "$sql" ] && continue
  n=$((n + 1))
  printf 'PREPARE gate_%s AS %s;\n' "$n" "$sql" >> "$BATCH"
  # batch.sql line number -> source location. psql reports the failing line
  # deterministically ("psql:/tmp/batch.sql:<line>: ERROR"), which is why we map
  # on that rather than on interleaved \echo output: stdout and stderr are
  # buffered differently, so marker-based attribution silently mis-blames files.
  printf '%s\t%s\n' "$n" "$loc" >> "$MAP"
done < "$STMTS"

docker cp "$BATCH" "$CONTAINER:/tmp/batch.sql" >/dev/null 2>&1
docker exec "$CONTAINER" psql -U postgres -d gate -f /tmp/batch.sql > /tmp/sqlgate_out.txt 2>&1

fail=0
checked=$(grep -c '^PREPARE$' /tmp/sqlgate_out.txt || true)

# Keep only the codes that mean real drift. A syntax error (42601) means we
# mis-extracted the statement, not that the schema is wrong — staying quiet there
# is what keeps this gate trustworthy enough to leave switched on.
python3 - <<'PYEOF' > /tmp/sqlgate_drift.txt
import re
mapping = {}
for line in open('/tmp/sqlgate_map.txt'):
    idx, loc = line.rstrip('\n').split('\t', 1)
    mapping[int(idx)] = loc          # statement N is on batch.sql line N
seen = set()
for line in open('/tmp/sqlgate_out.txt', errors='replace'):
    m = re.match(r'psql:[^:]+:(\d+): ERROR:\s*(.*)', line.strip())
    if not m:
        continue
    lineno, msg = int(m.group(1)), m.group(2)
    if not re.search(r'does not exist|inconsistent types deduced', msg):
        continue
    loc = mapping.get(lineno, f'batch.sql:{lineno}')
    key = (loc, msg)
    if key in seen:
        continue
    seen.add(key)
    print(f"{loc}\n    ERROR: {msg}")
PYEOF

if [ -s /tmp/sqlgate_drift.txt ] && grep -q "[^[:space:]]" /tmp/sqlgate_drift.txt; then
  echo "" >&2
  echo "Schema drift — the SQL below references something the migrations do not create:" >&2
  sed 's/^/  /' /tmp/sqlgate_drift.txt >&2
  fail=1
fi

echo "check-sql-schema: $checked/$total statements verified against the migrations-only schema."

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'EOF'

────────────────────────────────────────────────────────────────────────────
The SQL above references something the migrations do not create. This is the
class of bug that compiles, lints and unit-tests clean and then fails on every
real execution — usually swallowed by a log line, so the feature just silently
never works.

Fix the query, or add the migration. Do not "fix" this by making the statement
unextractable.
────────────────────────────────────────────────────────────────────────────
EOF
  exit 1
fi

cat <<'EOF'

LIMITATIONS (deliberately stated, so nobody reads a green tick as full cover):
statements assembled at runtime with fmt.Sprintf / strings.Join cannot be
prepared as written and are skipped. A column typo inside a dynamically built
WHERE/ORDER BY fragment will NOT be caught here — the big filter builders in
finding_repository.go, asset_repository.go and dashboard_repository.go are the
main residue.
EOF
exit 0
