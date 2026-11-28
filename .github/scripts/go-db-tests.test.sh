#!/usr/bin/env bash
# Tests go-db-tests.sh on a throw-away repository.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main .
git config user.email t@example.test; git config user.name t
mkdir -p server/p server/q server/migrations
t() { printf 'package %s\n\nimport "testing"\n\nfunc %s(t *testing.T) {}\n' "$1" "$2"; }
printf 'package p\n' > server/p/asset_repository.go
printf 'package p\n' > server/p/helpers.go
t p TestAssetA_DB > server/p/asset_db_test.go
t p TestAssetB > server/p/asset_list_db_test.go
t p TestOther > server/p/other_db_test.go
t p TestUnit > server/p/asset_test.go
printf 'package p\n\nimport "testing"\n\nfunc TestMain(m *testing.M) { m.Run() }\n\nfunc helper(t *testing.T) {}\n' > server/p/main_db_test.go
t q TestQ > server/q/q_db_test.go
echo 1 > server/migrations/1.sql
git add -A; git commit -q -m base
run() { GITHUB_OUTPUT="$tmp/out" bash "$here/go-db-tests.sh" main...HEAD 2>/dev/null >/dev/null; grep -E '^db(_pkgs|_run)?=' "$tmp/out" | paste -sd' '; rm -f "$tmp/out"; }
expect() { local got; got="$(run)"; [ "$got" = "$2" ] || { echo "FAIL $1: got '$got', want '$2'" >&2; exit 1; }; echo "ok $1"; }
change() { git checkout -q -B work main; "$@"; git add -A; git commit -q -m c; }

change sh -c 'echo "// x" >> server/q/q_db_test.go'
expect "a changed DB test runs its tests" "db=true db_pkgs=./q db_run=^(TestQ)\$"
change sh -c 'echo "// x" >> server/p/asset_repository.go'
expect "a repository runs the DB tests named after it" "db=true db_pkgs=./p db_run=^(TestAssetA_DB|TestAssetB)\$"
change sh -c 'echo "// x" >> server/p/asset_test.go; echo "// x" >> server/p/helpers.go'
expect "a unit test or a file no DB test is named after selects nothing" "db=false db_pkgs= db_run="
change sh -c 'echo "// x" >> server/p/main_db_test.go'
expect "TestMain and helpers are not tests" "db=false db_pkgs= db_run="
change sh -c 'echo 2 > server/migrations/2.sql'
expect "a migration alone selects nothing (schema and pg18 jobs run)" "db=false db_pkgs= db_run="
change git rm -q server/q/q_db_test.go
expect "a deleted DB test selects nothing" "db=false db_pkgs= db_run="
change sh -c 'echo "// x" >> server/q/q_db_test.go; echo "// x" >> server/p/other_db_test.go'
expect "two packages" "db=true db_pkgs=./p ./q db_run=^(TestOther|TestQ)\$"
echo "go-db-tests: all passed"
