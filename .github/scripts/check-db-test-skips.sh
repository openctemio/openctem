#!/usr/bin/env bash
# Fails when a `go test -json` run skipped a test because its database (or the
# Redis next to it) was missing or unusable.
#
# The DB-backed tests skip themselves when DATABASE_URL is unset or the
# database cannot be reached, which keeps `go test ./...` usable without
# Postgres. In the job that provides Postgres and Redis a skip like that means
# the isolation tests did not run while the job still went green. testdb
# already fails instead of skipping under OPENCTEM_TEST_DB_REQUIRED=1; this
# catches the tests that call t.Skip themselves on a failed ping or open.
#
# Usage: check-db-test-skips.sh <go-test-json-file>
set -euo pipefail

file="${1:?usage: check-db-test-skips.sh <go-test-json-file>}"

# Skip reasons that mean "no usable database / Redis". DATABASE_URL_RLS_TEST is
# optional (CI does not create the RLS test role), so it is not one of them.
pattern='DATABASE_URL(?!_RLS_TEST)|database not available|cannot reach|test DB|open db|testdb:|not migrated|run migration|migrations not applied|redis not available|REDIS_HOST not set'

skipped="$(
  jq -R -c 'try fromjson catch empty
    | select(.Test != null and (.Action == "output" or .Action == "skip"))
    | {k: (.Package + " " + .Test), a: .Action, o: (.Output // "")}' "$file" \
  | jq -r -s --arg re "$pattern" '
      group_by(.k)
      | map(select(any(.[]; .a == "skip")))
      | map({k: .[0].k, msg: (map(.o) | join("") | gsub("\\s+"; " "))})
      | map(select(.msg | test($re; "i")))
      | .[] | "\(.k): \(.msg)"'
)"

if [ -n "$skipped" ]; then
  echo "::error::DB-backed tests were skipped in the job that provides Postgres and Redis:"
  echo "$skipped"
  exit 1
fi
echo "No DB-backed test was skipped."
