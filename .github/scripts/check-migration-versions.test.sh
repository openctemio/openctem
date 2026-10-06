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
  out="$(cd "$d" && bash "$script" ${base:+"$base"} 2>&1)" || rc=$?
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

# 3. PR adds max+1: passes.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
mig "$d" 000006 c; commit "$d" pr
expect "added max+1 passes" 0 "$d" base

# 4. PR adds a version below the base's max (gap-filling is skipped by golang-migrate).
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
mig "$d" 000003 c; commit "$d" pr
expect "added below base max fails" 1 "$d" base "Renumber it to 000006"

# 5. Queue: the group ahead already took 000006; this PR also wrote 000006.
d="$(repo)"; mig "$d" 000005 b; commit "$d" base
mig "$d" 000006 first; commit "$d" "queued ahead"
git -C "$d" branch queue-base
mig "$d" 000006 second; commit "$d" "this pr"
expect "queue: same version as the group ahead fails" 1 "$d" queue-base "Renumber it to 000007"

# 6. Queue: this PR renumbered to 000007 on top.
d="$(repo)"; mig "$d" 000005 b; mig "$d" 000006 first; commit "$d" base
git -C "$d" branch queue-base
mig "$d" 000007 second; commit "$d" "this pr"
expect "queue: renumbered passes" 0 "$d" queue-base

# 7. Editing an existing migration is not an addition.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000002 b; commit "$d" base
git -C "$d" branch base
echo "-- note" >> "$d/api/migrations/000001_a.up.sql"; commit "$d" edit
expect "modifying an old migration passes" 0 "$d" base

# 8. A migration baseline replaces the chain up to its version (RFC-053).
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; mig "$d" 000009 c; commit "$d" base
git -C "$d" branch base
git -C "$d" rm -q api/migrations/00000[159]_*; mig "$d" 000009 baseline; mig "$d" 000010 after; commit "$d" squash
expect "baseline replacing the chain passes" 0 "$d" base

# 9. A baseline that leaves older migrations in the tree is just a low number.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 000005 b; commit "$d" base
git -C "$d" branch base
git -C "$d" rm -q api/migrations/000005_*; mig "$d" 000005 baseline; commit "$d" partial
expect "baseline above an older migration fails" 1 "$d" base "Renumber it to 000006"

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
