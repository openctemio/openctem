#!/usr/bin/env bash
# Tests for check-commit-emails.sh. Run: bash .github/scripts/check-commit-emails.test.sh
# Builds throwaway git repositories; touches nothing in this one.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-commit-emails.sh"
pass=0 failed=0
bad="@denied-corp"; bad="$bad.example" # built, so this file never holds a real denied domain

# repo: one base commit by an allowed identity; prints the directory.
repo() {
  local d; d="$(mktemp -d)"
  git -C "$d" init -q -b main
  git -C "$d" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m base
  echo "$d"
}
# commit <dir> <author email> <committer email> <message>
commit() {
  GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL="$2" GIT_COMMITTER_NAME=c GIT_COMMITTER_EMAIL="$3" \
    git -C "$1" commit -q --allow-empty -m "$4"
}

# expect <name> <0|1> <repo> <denylist> [must-contain]
expect() {
  local name="$1" want="$2" d="$3" deny="$4" needle="${5:-}" out rc=0
  out="$(cd "$d" && COMMIT_EMAIL_DENYLIST="$deny" bash "$script" "main~$(($(git -C "$d" rev-list --count main) - 1))..main" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$want" ]] || [[ -n "$needle" && "$out" != *"$needle"* ]] || [[ "${out,,}" == *"${bad,,}"* ]]; then
    echo "FAIL: $name (exit $rc, want $want)"; echo "$out"; failed=$((failed + 1))
  else
    echo "ok:   $name"; pass=$((pass + 1))
  fi
}

d="$(repo)"; commit "$d" me@example.org me@example.org "clean"
expect "allowed identities pass" 0 "$d" "$bad"
expect "empty deny list skips" 0 "$d" "" "skipped"

d="$(repo)"; commit "$d" "x${bad}" noreply@github.com "authored"
expect "denied author fails" 1 "$d" "$bad" "(author)"

d="$(repo)"; commit "$d" me@example.org "X${bad^^}" "committed"
expect "denied committer fails, case-insensitive" 1 "$d" "$bad" "(committer)"

d="$(repo)"; commit "$d" me@example.org me@example.org $'trailer\n\nCo-authored-by: Someone <y'"$bad"'>'
expect "denied co-author trailer fails" 1 "$d" "$bad" "Co-authored-by trailer"

d="$(repo)"; commit "$d" me@example.org me@example.org "one"; commit "$d" "z${bad}" "z${bad}" "two"
expect "comma list, any entry matches" 1 "$d" "@other.example, ${bad}" "(author, committer)"

d="$(repo)"; commit "$d" me@example.org me@example.org "clean"
rng="main~$(($(git -C "$d" rev-list --count main) - 1))..main"
for v in "" $'\n , '; do
  rc=0; (cd "$d" && REQUIRE_DENYLIST=true COMMIT_EMAIL_DENYLIST="$v" bash "$script" "$rng" >/dev/null 2>&1) || rc=$?
  if [[ "$rc" -eq 1 ]]; then echo "ok:   required: unset/empty list fails closed"; pass=$((pass + 1)); else echo "FAIL: required list missing (exit $rc)"; failed=$((failed + 1)); fi
done

out="$(COMMIT_EMAIL_DENYLIST="$bad" bash "$script" "" 2>&1)"
if [[ "$out" == *"skipped"* ]]; then echo "ok:   no range skips"; pass=$((pass + 1)); else echo "FAIL: no range skips"; failed=$((failed + 1)); fi

echo "passed $pass, failed $failed"
[[ "$failed" -eq 0 ]]
