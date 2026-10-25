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
run() { (cd "$1" && bash "$script" 2>&1); }
files() { (cd "$1/api/migrations" && ls | tr '\n' ' '); }

check() { # check <name> <condition result 0|1> [output]
  if [[ "$2" -eq 0 ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1"; echo "${3:-}"; failed=$((failed + 1)); fi
}

# 1. No clash: nothing changes.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 b; commit "$d" pr
merge "$d"; out="$(run "$d")"
ok=0; [[ "$(files "$d")" == "000001_a.down.sql 000001_a.up.sql 000002_b.down.sql 000002_b.up.sql " && "$out" == *"no clash"* ]] || ok=1
check "no clash leaves the tree alone" $ok "$out"

# 2. Develop took the PR's number: the PR's migration moves above the base.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 mine; commit "$d" pr
echo 'v := testdb.MigrationVersion(t, dir, "mine") // 000002_mine' > "$d/api/tests/x_test.go"; commit "$d" "pr test"
git -C "$d" checkout -q base; mig "$d" 000002 theirs; mig "$d" 000003 more; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/000004_mine.up.sql" && -e "$d/api/migrations/000004_mine.down.sql" && ! -e "$d/api/migrations/000002_mine.up.sql" \
  && "$(cat "$d/api/tests/x_test.go")" == *"000004_mine"* && "$out" == *"::warning::"*"renumbered to 000004"* ]] || ok=1
check "a duplicate version moves above the base and references follow" $ok "$out"

# 3. Two own migrations keep their order; one below and one above the base max.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 first; mig "$d" 000009 second; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 theirs; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/000006_first.up.sql" && -e "$d/api/migrations/000007_second.up.sql" ]] || ok=1
check "own migrations are renumbered in order above the base" $ok "$out"

# 4. A stacked PR's byte-identical copy of a merged migration is dropped.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 parent "create table p();"; mig "$d" 000003 child; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000005 parent "create table p();"; commit "$d" "parent merged renumbered"
merge "$d"; out="$(run "$d")"
ok=0; [[ ! -e "$d/api/migrations/000002_parent.up.sql" && -e "$d/api/migrations/000005_parent.up.sql" && -e "$d/api/migrations/000006_child.up.sql" ]] || ok=1
check "an identical copy of a base migration is ignored, the rest renumbered" $ok "$out"

# 5. Same name, different content: not a copy, renumbered instead.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 same "create table x();"; commit "$d" pr
git -C "$d" checkout -q base; mig "$d" 000002 other; commit "$d" "develop moved"
merge "$d"; out="$(run "$d")"
ok=0; [[ -e "$d/api/migrations/000003_same.up.sql" ]] || ok=1
check "a different migration is never dropped" $ok "$out"

# 6. Missing base commit: a notice, no change.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base
rc=0; out="$(cd "$d" && bash "$script" deadbeef 2>&1)" || rc=$?
ok=0; [[ "$rc" -eq 0 && "$out" == *"::notice::"* ]] || ok=1
check "an unavailable base is a notice" $ok "$out"

# 7. Another open PR took the number above the base: move above it too.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000002 mine; mig "$d" 000003 mine2; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_TAKEN="000002 7" bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/000008_mine.up.sql" && -e "$d/api/migrations/000009_mine2.up.sql" ]] || ok=1
check "a version another open PR takes moves above every taken one" $ok "$out"

# 8. Taken versions that do not clash change nothing.
d="$(repo)"; mig "$d" 000001 a; commit "$d" base; pr "$d"; mig "$d" 000005 mine; commit "$d" pr
merge "$d"; out="$(cd "$d" && MIGRATION_TAKEN="2 3" bash "$script" 2>&1)"
ok=0; [[ -e "$d/api/migrations/000005_mine.up.sql" && "$out" == *"no clash"* ]] || ok=1
check "taken versions that do not clash leave the tree alone" $ok "$out"

echo "passed: $pass, failed: $failed"
(( failed == 0 ))
