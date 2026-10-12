#!/usr/bin/env bash
# Tests for check-ci.sh with recorded check runs (no network).
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
CI="$RELEASE_DIR/check-ci.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CHECK_RUNS_DIR="$tmp/runs"
export REQUIRED_CHECKS="API CI OK, Web CI OK"
mkdir -p "$CHECK_RUNS_DIR"

new_repo "$tmp/r"
commit "$tmp/r" "one"; c1="$(git -C "$tmp/r" rev-parse HEAD)"
commit "$tmp/r" "two"; c2="$(git -C "$tmp/r" rev-parse HEAD)"
commit "$tmp/r" "three"; c3="$(git -C "$tmp/r" rev-parse HEAD)"

run() { printf '{"name":"%s","status":"%s","conclusion":%s,"id":%s}' "$1" "$2" "$3" "$4"; }
# c1: all green.
echo "[$(run 'API CI OK' completed '"success"' 1),$(run 'Web CI OK' completed '"success"' 2),$(run 'Other' completed '"failure"' 3)]" >"$CHECK_RUNS_DIR/$c1.json"
# c2: API was cancelled, then re-run green (the latest run wins); web failed.
echo "[$(run 'API CI OK' completed '"cancelled"' 10),$(run 'API CI OK' completed '"success"' 11),$(run 'Web CI OK' completed '"failure"' 12)]" >"$CHECK_RUNS_DIR/$c2.json"
# c3: web still running; nothing for API.
echo "[$(run 'Web CI OK' in_progress null 20)]" >"$CHECK_RUNS_DIR/$c3.json"

out="$(bash "$CI" "$c1" 2>&1)"; rc=$?
assert_eq "green commit: exit 0" 0 "$rc"
assert_contains "green commit: lists checks" "API CI OK	success" "$out"
assert_not_contains "a check that is not required does not count" "Other" "$out"

out="$(bash "$CI" "$c2" 2>&1)"; rc=$?
assert_eq "red commit: exit 1" 1 "$rc"
assert_contains "latest run wins (re-run green)" "API CI OK	success" "$out"
assert_contains "failure reported" "Web CI OK	failure" "$out"

out="$(bash "$CI" "$c3" 2>&1)"; rc=$?
assert_eq "pending commit: exit 1" 1 "$rc"
assert_contains "missing check" "API CI OK	missing" "$out"
assert_contains "pending check" "Web CI OK	in_progress" "$out"

# No recorded runs at all: red.
commit "$tmp/r" "four"; c4="$(git -C "$tmp/r" rev-parse HEAD)"
assert_rc "no runs: red" 1 bash "$CI" "$c4"

# Newest green walks back first-parent history.
assert_eq "newest green" "$c1" "$(bash "$CI" --newest-green HEAD --repo "$tmp/r" 2>/dev/null)"
assert_rc "none green within --max" 1 bash "$CI" --newest-green HEAD --max 2 --repo "$tmp/r"

finish
