#!/usr/bin/env bash
# Tests for check-next-no-migrations.sh. Run: bash .github/scripts/check-next-no-migrations.test.sh
# Builds a throwaway repository with a develop and a next branch; touches nothing else.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-next-no-migrations.sh"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
pass=0 failed=0
r="$tmp/repo"
g() { git -C "$r" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false "$@"; }

git init -q -b develop "$r"
mkdir -p "$r/server/migrations" "$r/web"
echo "create table a();" >"$r/server/migrations/20260101000000_a.up.sql"
echo "page" >"$r/web/page.tsx"
g add -A; g commit -qm base
g branch next
# develop moves on: one new migration, merged there.
echo "create table b();" >"$r/server/migrations/20260201000000_b.up.sql"
g add -A; g commit -qm "develop: migration b"
dev="$(g rev-parse develop)"

# head <name> <from> <cmds...>: a branch from <from>, the commands run inside it, committed.
head() {
  local name="$1" from="$2"; shift 2
  g checkout -q -b "$name" "$from"
  (cd "$r" && eval "$*")
  g add -A; g commit -qm "$name" --allow-empty
  g checkout -q develop
}
head web-only next 'echo new >web/page.tsx'
head adds-migration next 'echo "create table c();" >server/migrations/20260301000000_c.up.sql'
head edits-migration next 'echo "create table a(x int);" >server/migrations/20260101000000_a.up.sql'
head removes-migration next 'git rm -q server/migrations/20260101000000_a.up.sql'
head picks-develop next 'git checkout -q develop -- server/migrations/20260201000000_b.up.sql'
head sync next "git -c user.name=t -c user.email=t@example.com merge -q --no-edit develop"
head sync-plus-own next "git -c user.name=t -c user.email=t@example.com merge -q --no-edit develop; echo 'drop table a;' >server/migrations/20260401000000_d.up.sql"
head into-develop develop 'echo "create table e();" >server/migrations/20260501000000_e.up.sql'

# PR: HEAD is the head commit merged onto next (GitHub's refs/pull/N/merge).
pr() { # pr <name> <want rc> <head branch> [base]
  local out rc=0 base="${4:-next}"
  g checkout -q --detach "$base"
  g -c user.name=t -c user.email=t@example.com merge -q --no-ff --no-edit "$3" >/dev/null 2>&1
  g update-ref refs/remotes/origin/next next
  out="$(cd "$r" && EVENT=pull_request BASE_REF="$base" DEVELOP="$dev" bash "$script" 2>&1)" || rc=$?
  g checkout -q develop
  if [[ "$rc" -ne "$2" ]] || { [[ "$2" -eq 1 ]] && [[ "$out" != *"next takes no database migrations"* ]]; }; then echo "FAIL: $1 (exit $rc, want $2)"; echo "$out"; failed=$((failed + 1)); else echo "ok:   $1"; pass=$((pass + 1)); fi
}
mg() { # mg <name> <want rc> <head branch> [base ref]
  local out rc=0 bref="${4:-refs/heads/next}" b h
  b="$(g rev-parse next)"
  g checkout -q --detach next
  g -c user.name=t -c user.email=t@example.com merge -q --no-ff --no-edit "$3" >/dev/null 2>&1
  h="$(g rev-parse HEAD)"
  out="$(cd "$r" && EVENT=merge_group MG_BASE_REF="$bref" MG_BASE="$b" MG_HEAD="$h" DEVELOP="$dev" bash "$script" 2>&1)" || rc=$?
  g checkout -q develop
  if [[ "$rc" -ne "$2" ]] || { [[ "$2" -eq 1 ]] && [[ "$out" != *"next takes no database migrations"* ]]; }; then echo "FAIL: $1 (exit $rc, want $2)"; echo "$out"; failed=$((failed + 1)); else echo "ok:   $1"; pass=$((pass + 1)); fi
}

pr "PR into next without migrations passes" 0 web-only
pr "PR into next adding a migration fails" 1 adds-migration
pr "PR into next editing a merged migration fails" 1 edits-migration
pr "PR into next removing a migration fails" 1 removes-migration
pr "PR into next taking develop's merged migration as is passes" 0 picks-develop
pr "sync PR (develop merged into next) passes" 0 sync
pr "sync PR that also adds its own migration fails" 1 sync-plus-own
pr "PR into develop is not checked" 0 into-develop develop
mg "merge group for next adding a migration fails" 1 adds-migration
mg "merge group for next with the sync passes" 0 sync
mg "merge group for develop is not checked" 0 adds-migration refs/heads/develop

out="$(cd "$r" && EVENT=merge_group MG_BASE_REF=refs/heads/next MG_BASE='' MG_HEAD='' DEVELOP="$dev" bash "$script" 2>&1)" && rc=0 || rc=$?
if [[ "$rc" -eq 1 ]]; then echo "ok:   merge group for next without shas fails"; pass=$((pass + 1)); else echo "FAIL: merge group without shas (exit $rc)"; failed=$((failed + 1)); fi
out="$(cd "$r" && EVENT=push DEVELOP="$dev" bash "$script" 2>&1)" && rc=0 || rc=$?
if [[ "$rc" -eq 0 ]]; then echo "ok:   a push is not checked"; pass=$((pass + 1)); else echo "FAIL: push (exit $rc)"; failed=$((failed + 1)); fi

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
