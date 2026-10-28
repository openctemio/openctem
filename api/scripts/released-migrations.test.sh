#!/usr/bin/env bash
# Tests for released-migrations.sh. Run: bash api/scripts/released-migrations.test.sh
# Builds a throwaway git repository; touches nothing in this one.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/released-migrations.sh"
pass=0 failed=0
check() { if [[ "$2" -eq 0 ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1"; echo "${3:-}"; failed=$((failed + 1)); fi; }

d="$(mktemp -d)"
git -C "$d" init -q -b main
git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
mkdir -p "$d/api/migrations" "$d/api/cmd"
mig() { touch "$d/api/migrations/$1_$2.up.sql" "$d/api/migrations/$1_$2.down.sql"; }
commit() { git -C "$d" add -A; git -C "$d" commit -qm "$1"; }

mig 001146 baseline; mig 003419 a; mig 003428 c; commit r1; git -C "$d" tag v0.15.3
git -C "$d" tag v0.15.4
mig 003420 late; commit late # merged after the release, below its last migration
mig 20261027000001 stamp; mkdir -p "$d/api/cmd/openctem-migrate"; touch "$d/api/cmd/openctem-migrate/main.go"; commit runner
git -C "$d" tag v0.16.0 # ships the runner: not listed

out="$(cd "$d" && bash "$script" 2>&1)"
json="$(cat "$d/api/migrations/released.json")"
ok=0; [[ "$json" == *'{"tags": ["v0.15.3", "v0.15.4"], "versions": [1146,3419,3428]}'* && "$json" != *v0.16.0* && "$json" != *3420* ]] || ok=1
check "lists each release's versions, groups equal sets, skips releases with the runner" $ok "$json"

commit released
rc=0; out="$(cd "$d" && bash "$script" --check 2>&1)" || rc=$?
check "check passes on a fresh file" "$rc" "$out"

echo '{}' >"$d/api/migrations/released.json"
rc=0; out="$(cd "$d" && bash "$script" --check 2>&1)" || rc=$?
ok=0; [[ "$rc" -ne 0 && "$out" == *"does not match the release tags"* ]] || ok=1
check "check fails on a stale file" $ok "$out"

git -C "$d" tag -d v0.15.3 v0.15.4 v0.16.0 >/dev/null
rc=0; out="$(cd "$d" && bash "$script" --check 2>&1)" || rc=$?
ok=0; [[ "$rc" -ne 0 && "$out" == *"no release tags"* ]] || ok=1
check "check fails without tags" $ok "$out"

echo "passed: $pass, failed: $failed"
(( failed == 0 ))
