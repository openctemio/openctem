#!/usr/bin/env bash
# Tests for check-migration-versions.sh. Run: bash .github/scripts/check-migration-versions.test.sh
# Builds throwaway git repositories; touches nothing in this one.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-migration-versions.sh"
pass=0 failed=0

repo() {
  local d; d="$(mktemp -d)"
  git -C "$d" init -q -b main
  git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
  mkdir -p "$d/api/migrations/seed"
  echo "$d"
}
mig() { # mig <repo> <version> <name>
  touch "$1/api/migrations/$2_$3.up.sql" "$1/api/migrations/$2_$3.down.sql"
}
commit() { git -C "$1" add -A; git -C "$1" commit -qm "$2"; }

# expect <name> <0|1> <repo> [base] [output-substring]
expect() {
  local name="$1" want="$2" d="$3" base="${4:-}" needle="${5:-}" out rc=0
  out="$(cd "$d" && MIGRATION_DUPLICATE="${MODE:-error}" bash "$script" ${base:+"$base"} 2>&1)" || rc=$?
  if [[ "$rc" -ne "$want" ]] || [[ -n "$needle" && "$out" != *"$needle"* ]]; then
    echo "FAIL: $name (exit $rc, want $want)"; echo "$out"; failed=$((failed + 1))
  else
    echo "ok:   $name"; pass=$((pass + 1))
  fi
}

# 1. Clean tree, no base.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000002 b; touch "$d/api/migrations/seed/x.sql"; commit "$d" base
expect "distinct versions pass" 0 "$d"

# 2. Two migrations share a version (the #767/#773 case after both merged).
mig "$d" 000002 c; commit "$d" dup
expect "duplicate version fails" 1 "$d" "" "version 2 is used more than once"

T1=20261027101500 T2=20261027101600 T3=20261026090000

# 3. PR adds a timestamp version: passes.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
mig "$d" "$T1" c; commit "$d" pr
expect "added timestamp version passes" 0 "$d" base

# 4. A timestamp below the base's highest (written earlier, merged later) is fine.
d="$(repo)"; mig "$d" 000001 a; mig "$d" "$T2" b; commit "$d" base
git -C "$d" branch base
mig "$d" "$T3" c; commit "$d" pr
expect "added version below the base max passes" 0 "$d" base

# 4a. A legacy sequential number above the base's passes with a warning; one
# at or below it fails (a takeover would record it as applied), and only
# warns on a pull request (PR CI gives it a timestamp).
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
mig "$d" 000006 up; commit "$d" pr
expect "added legacy number above the base's only warns" 0 "$d" base "::warning::api/migrations/000006_up has a sequential version"
mig "$d" 000003 c; commit "$d" pr2
expect "added legacy number below the base's fails" 1 "$d" base "has the sequential version 3, at or below the base's highest (5)"
MODE=warning expect "pull_request: added legacy number below the base's only warns" 0 "$d" base "::warning::api/migrations/000003_c has the sequential version 3"

# 4a'. Once the base has a timestamp version, any added legacy number fails,
# in both modes: a database the earlier tool migrated to a timestamp version
# is past every legacy number, so a takeover would record it without running it.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; mig "$d" "$T2" t; commit "$d" base
git -C "$d" branch base
mig "$d" 000006 up; commit "$d" pr
expect "added legacy number after a timestamp version fails" 1 "$d" base "base already has timestamp versions"
MODE=warning expect "pull_request: added legacy number after a timestamp version fails" 1 "$d" base "Renumber with make -C api migration-renumber"
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base

# 4b. Warning mode: a version the base also uses only warns (PR CI renumbers it).
mig "$d" 000005 dupe; commit "$d" dup
MODE=warning expect "pull_request: same version as a base migration only warns" 0 "$d" base "give this change's copy a new version"
expect "error mode: duplicate version fails" 1 "$d" base "used more than once"

# 4c. Warning mode still fails two added migrations sharing a version.
mig "$d" 000007 x; mig "$d" 000007 y; commit "$d" own-dup
MODE=warning expect "pull_request: two added migrations with one version fail" 1 "$d" base "::error::migration version 7"

# 4d. Malformed versions: not a timestamp, not a legacy number.
for bad in 2026102710150 202610271015000 20261327101500 20260231101500 20261027246000 20251027101500; do
  d="$(repo)"; mig "$d" 000001 a; commit "$d" base
  git -C "$d" branch base
  mig "$d" "$bad" c; commit "$d" pr
  expect "added version $bad fails" 1 "$d" base "must be a UTC timestamp"
done

# 5. Queue: the group ahead already took a version this PR also wrote.
d="$(repo)"; mig "$d" 000005 b; commit "$d" base
mig "$d" 000006 first; commit "$d" "queued ahead"
git -C "$d" branch queue-base
mig "$d" 000006 second; commit "$d" "this pr"
expect "queue: same version as the group ahead fails" 1 "$d" queue-base "used more than once"
MODE=warning expect "warning mode: same version as base only warns" 0 "$d" queue-base "::warning::migration version 6"

# 6. Queue: timestamps of parallel PRs never meet.
d="$(repo)"; mig "$d" 000005 b; mig "$d" "$T2" first; commit "$d" base
git -C "$d" branch queue-base
mig "$d" "$T1" second; commit "$d" "this pr"
expect "queue: an older timestamp behind a newer one passes" 0 "$d" queue-base

# 7. Editing a merged up file fails; editing a down file passes.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000002 b; commit "$d" base
git -C "$d" branch base
echo "-- note" >> "$d/api/migrations/000001_a.down.sql"; commit "$d" edit-down
expect "fixing a merged down file passes" 0 "$d" base
echo "-- note" >> "$d/api/migrations/000001_a.up.sql"; commit "$d" edit-up
expect "changing a merged up file fails" 1 "$d" base "000001_a.up.sql is changed, but it has merged"

# 7b. Renumbering or removing a merged migration fails.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000002 b; commit "$d" base
git -C "$d" branch base
git -C "$d" mv api/migrations/000002_b.up.sql "api/migrations/${T1}_b.up.sql"
git -C "$d" mv api/migrations/000002_b.down.sql "api/migrations/${T1}_b.down.sql"; commit "$d" renumber
expect "renumbering a merged migration fails" 1 "$d" base "000002_b.up.sql is removed or renamed"

# 8. A migration baseline replaces the chain up to its version (RFC-053).
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; mig "$d" 000009 c; commit "$d" base
git -C "$d" branch base
git -C "$d" rm -q api/migrations/00000[159]_*; mig "$d" 000009 baseline; mig "$d" "$T1" after; commit "$d" squash
expect "baseline replacing the chain passes" 0 "$d" base

# 9. A baseline that leaves older migrations in the tree removes a merged one.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
git -C "$d" rm -q api/migrations/000005_*; mig "$d" 000005 baseline; commit "$d" partial
expect "baseline above an older migration fails" 1 "$d" base "000005_b.up.sql is removed or renamed"

# 10. A push to develop that skipped the queue: the base is develop before the
# push; a lower version is fine now, a duplicate is not.
d="$(repo)"; mig "$d" 000005 b; commit "$d" base
git -C "$d" checkout -q -b feature; mig "$d" "$T3" late; commit "$d" "feature"
git -C "$d" checkout -q main; mig "$d" "$T2" ahead; commit "$d" "develop moved on"
git -C "$d" branch before-push
git -C "$d" merge -q --no-ff -m "direct merge" feature
expect "direct merge below develop's highest passes" 0 "$d" before-push
d="$(repo)"; mig "$d" 000005 b; commit "$d" base
git -C "$d" checkout -q -b feature; mig "$d" 000008 mine; commit "$d" "feature"
git -C "$d" checkout -q main; mig "$d" 000008 ahead; commit "$d" "develop moved on"
git -C "$d" branch before-push
git -C "$d" merge -q --no-ff -m "direct merge" feature
expect "direct merge with a duplicate version fails" 1 "$d" before-push "used more than once"

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
