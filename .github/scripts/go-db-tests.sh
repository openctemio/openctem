#!/usr/bin/env bash
# The DB-backed Go tests a pull request runs (api-ci.yml `dbtests`): the
# top-level tests of the *_db_test.go files it adds or changes, plus those of
# the *_db_test.go files named after a non-test Go file it changes. Without
# this a DB test changed in a PR first runs in the merge queue (the fast tier
# has no database there), and a broken one evicts its group.
#
#   go-db-tests.sh <git range>      (run from the repository root)
#
# Writes to $GITHUB_OUTPUT (stdout without it):
#   db=true|false   something to run
#   db_pkgs=<dirs>  package directories relative to server/ (./internal/...),
#                   space separated
#   db_run=<regex>  ^(TestA|TestB|...)$ over every selected test
#
# A changed <dir>/<stem>.go (not a test) selects <dir>/<stem>_db_test.go and
# <dir>/<stem>_*_db_test.go, and the same with a trailing _repository dropped
# from the stem (asset_repository.go -> asset_*_db_test.go). Deleted files
# select nothing. A test file without top-level tests (helpers) selects nothing;
# the unit job still compiles it. Migrations select nothing here: the schema
# job and Migrations (PostgreSQL 18) run for them, and a migration's own test
# is a *_db_test.go. The merge queue still runs the whole suite.
set -euo pipefail

range="${1:?usage: go-db-tests.sh <git range>}"
cd "$(git rev-parse --show-toplevel)"
out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/stdout}"; [ -z "${GITHUB_OUTPUT:-}" ] || echo "$1=$2"; }

changed="$(git diff --name-only --diff-filter=d "$range" -- 'server/*.go')"

declare -A files=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  dir="$(dirname "$f")" base="$(basename "$f" .go)"
  case "$base" in
    *_db_test) files["$f"]=1; continue ;;
    *_test) continue ;;
  esac
  for stem in "$base" "${base%_repository}"; do
    [ -n "$stem" ] || continue
    for t in "$dir/${stem}_db_test.go" "$dir/${stem}"_*_db_test.go; do
      if [ -f "$t" ]; then files["$t"]=1; fi
    done
  done
done <<<"$changed"

declare -A pkgs=() names=()
for f in "${!files[@]}"; do
  [ -f "$f" ] || continue
  dir="$(dirname "$f")"; dir="./${dir#server/}"
  # Only plain paths and identifiers reach the go test command line.
  [[ "$dir" =~ ^\./[A-Za-z0-9_./-]+$ ]] || { echo "skipping unexpected path: $f" >&2; continue; }
  found=0
  while IFS= read -r n; do
    [[ "$n" =~ ^Test[A-Za-z0-9_]*$ ]] || continue
    names["$n"]=1; found=1
  done < <(sed -nE 's/^func (Test[A-Za-z0-9_]*)\([A-Za-z_][A-Za-z0-9_]* \*testing\.T\).*/\1/p' "$f")
  if [ "$found" = 1 ]; then pkgs["$dir"]=1; fi
  echo "  $f" >&2
done

if [ "${#names[@]}" -eq 0 ]; then
  out db false; out db_pkgs ""; out db_run ""
  echo "no DB-backed test file changed or named after a changed file" >&2
  exit 0
fi
p="$(printf '%s\n' "${!pkgs[@]}" | sort | paste -sd' ')"
r="^($(printf '%s\n' "${!names[@]}" | sort | paste -sd'|'))\$"
echo "${#names[@]} tests in ${#pkgs[@]} packages" >&2
out db true; out db_pkgs "$p"; out db_run "$r"
