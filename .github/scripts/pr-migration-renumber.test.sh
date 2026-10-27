#!/usr/bin/env bash
# Tests for pr-migration-renumber.sh. Run: bash .github/scripts/pr-migration-renumber.test.sh
# Builds throwaway git repositories shaped like a pull request's test merge
# (HEAD = merge of the PR into the base, HEAD^1 = the base); touches nothing here.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/pr-migration-renumber.sh"
pass=0 failed=0

repo() {
  local d; d="$(mktemp -d)"
  git -C "$d" init -q -b base
  git -C "$d" config user.name t; git -C "$d" config user.email t@example.invalid
  mkdir -p "$d/api/migrations" "$d/api/tests"
  echo "$d"
}
mig() { # mig <repo> <version> <name> [content]
  echo "${4:--- $3}" > "$1/api/migrations/$2_$3.up.sql"
  echo "-- down $3" > "$1/api/migrations/$2_$3.down.sql"
}
commit() { git -C "$1" add -A; git -C "$1" commit -qm "$2"; }
# pr <repo>: start the PR branch from the current base commit.
pr() { git -C "$1" checkout -qb pr; }
# merge <repo>: back to the base and make the test merge commit of the PR.
merge() { git -C "$1" checkout -q base; git -C "$1" checkout -qb test-merge; git -C "$1" merge -q --no-ff --no-edit pr; }
files() { (cd "$1/api/migrations" && ls | tr '\n' ' '); }

check() { # check <name> <condition result 0|1> [output]
  if [[ "$2" -eq 0 ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1"; echo "${3:-}"; failed=$((failed + 1)); fi
}

T=20261027101500 # MIGRATION_NOW of every run
run() { (cd "$1" && MIGRATION_NOW=$T bash "$script" 2>&1); }

# 1. No clash: nothing changes.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 b; commit "$d" pr
merge "$d"; out="$(run "$d")"
ok=0; [[ "$(files "$d")" == "000001_a.down.sql 000001_a.up.sql 000002_b.down.sql 000002_b.up.sql " && "$out" == *"no clash"* ]] || ok=1
check "no clash leaves the tree alone" $ok "$out"

# 2. Develop took the PR's number: the PR's migration gets a timestamp.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 mine; commit "$d" pr
echo 'v := testdb.MigrationVersion(t, dir, "mine") // 000002_mine' > "$d/api/tests/x_test.go"; commit "$d" "pr test"
git -C "$d" checkout -q base; mig "$d" 000002 theirs; mig "$d" 000003 more; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/${T}_mine.up.sql" && -e "$d/api/migrations/${T}_mine.down.sql" && ! -e "$d/api/migrations/000002_mine.up.sql" \
  && "$(cat "$d/api/tests/x_test.go")" == *"${T}_mine"* && "$out" == *"::warning::"*"renumbered to ${T}"* ]] || ok=1
check "a duplicate version gets a timestamp and references follow" $ok "$out"

# 3. A unique timestamp below the base's highest is fine: left alone. A
# legacy number below the base's highest legacy one gets a timestamp.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 20261020080000 first; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 20261026080000 theirs; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/20261020080000_first.up.sql" && "$out" == *"no clash"* ]] || ok=1
check "a unique timestamp below the base max is left alone" $ok "$out"
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 first; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 theirs; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/${T}_first.up.sql" ]] || ok=1
check "a legacy number below the base's legacy max gets a timestamp" $ok "$out"

# 3b. Once the base has a timestamp version, a legacy number above the base's
# legacy max still gets a timestamp (a takeover from a timestamp version
# would record it as applied without running it).
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000009 late; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 theirs; mig "$d" 20261026080000 stamp; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/${T}_late.up.sql" && ! -e "$d/api/migrations/000009_late.up.sql" ]] || ok=1
check "a legacy number after the base has a timestamp version gets a timestamp" $ok "$out"
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000009 late; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 theirs; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/000009_late.up.sql" && "$out" == *"no clash"* ]] || ok=1
check "a legacy number above a legacy-only base is left alone" $ok "$out"

# 4. A stacked PR's byte-identical copy of a merged migration is dropped.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 parent "create table p();"; mig "$d" 000003 child; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 parent "create table p();"; commit "$d" "parent merged renumbered"
merge "$d"; out="$(run "$d")"
ok=0; [[ ! -e "$d/api/migrations/000002_parent.up.sql" && -e "$d/api/migrations/000005_parent.up.sql" && -e "$d/api/migrations/${T}_child.up.sql" ]] || ok=1
check "an identical copy of a base migration is ignored, the rest renumbered" $ok "$out"

# 5. Same name, different content, same version: not a copy, renumbered.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 same "create table x();"; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000002 other; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/${T}_same.up.sql" ]] || ok=1
check "a different migration is never dropped" $ok "$out"

# 6. Missing base commit: a notice, no change.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base
rc=0; out="$(cd "$d" && bash "$script" deadbeef 2>&1)" || rc=$?
ok=0; [[ "$rc" -eq 0 && "$out" == *"::notice::"* ]] || ok=1
check "an unavailable base is a notice" $ok "$out"

# 7. Another open PR took the first number: it and every later one move, in order.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 mine; mig "$d" 000003 mine2; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_NOW=$T MIGRATION_TAKEN="000002 7" bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/${T}_mine.up.sql" && -e "$d/api/migrations/20261027101501_mine2.up.sql" ]] || ok=1
check "a taken version moves, and the migrations after it keep their order" $ok "$out"

# 8. Taken versions that do not clash change nothing.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000005 mine; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_NOW=$T MIGRATION_TAKEN="2 3" bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/000005_mine.up.sql" && "$out" == *"no clash"* ]] || ok=1
check "taken versions that do not clash leave the tree alone" $ok "$out"

# 9. Legacy mode: a sequential number becomes a timestamp; what follows it keeps its order.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 20261020080000 newer; mig "$d" 000002 old; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_NOW=$T MIGRATION_RENUMBER_LEGACY=1 bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/${T}_old.up.sql" && -e "$d/api/migrations/20261027101501_newer.up.sql" ]] || ok=1
check "legacy mode moves a sequential number to a timestamp, keeping the order" $ok "$out"

# 10. Timestamps roll over minutes and days, and skip versions in use.
d="$(repo)"; mig "$d" 000001 a; mig "$d" 20261027235959 used; commit "$d" base; pr "$d"; mig "$d" 000001 x; mig "$d" 000002 y; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_NOW=20261027235959 bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/20261028000000_x.up.sql" && -e "$d/api/migrations/20261028000001_y.up.sql" ]] || ok=1
check "timestamps are valid times and unused" $ok "$out"

echo "passed: $pass, failed: $failed"
(( failed == 0 ))
