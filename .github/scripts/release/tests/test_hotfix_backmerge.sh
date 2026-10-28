#!/usr/bin/env bash
# Tests for post-release.sh on a hotfix whose picks develop already has: the
# merge conflicts only because develop moved on, so the back-merge is -s ours.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
POST="$RELEASE_DIR/post-release.sh"
CUT="$RELEASE_DIR/cut-release.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scenario "$tmp"
w="$tmp/work"
# develop already carries v0.2.0 (the post-release merge of the last train).
git -C "$w" merge -q -s ours -m "chore: merge v0.2.0 back" v0.2.0
git -C "$w" push -q origin develop
fix="$(git -C "$w" log --format=%H --grep '^fix(api): after release' -n 1 develop)"

# Cut the hotfix with the real script, release it on main (v0.2.1).
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$fix" --push 2>/dev/null)"
rel="$(sed -n 's/^HEAD=//p' <<<"$out")"
git -C "$w" switch -q main
git -C "$w" merge -q --ff-only "$rel"
git -C "$w" tag -a v0.2.1 -m v0.2.1
git -C "$w" push -q origin main --tags
git -C "$w" switch -q develop
# develop moved on in the same file, so merging the tag conflicts.
echo "later line" >>"$w/d.txt"
git -C "$w" commit -qam "fix(api): more on d"
git -C "$w" push -q origin develop
devtree="$(git -C "$w" rev-parse 'develop^{tree}')"

out="$(bash "$POST" --repo "$w" --version v0.2.1 --mode hotfix --push 2>"$tmp/err")"; rc=$?
assert_eq "all picks on develop: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
ph="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_rc "all picks on develop: the tag is an ancestor" 0 git -C "$w" merge-base --is-ancestor v0.2.1 "$ph"
assert_eq "all picks on develop: develop's tree kept" "$devtree" "$(git -C "$w" rev-parse "${ph}^{tree}")"
assert_eq "all picks on develop: CHANGED is empty" "" "$(sed -n 's/^CHANGED=//p' <<<"$out")"
assert_eq "all picks on develop: a merge commit" 3 "$(git -C "$w" rev-list --parents -n 1 "$ph" | wc -w)"

# The same conflict in train mode is still refused (-s ours only for hotfix).
git -C "$w" push -q origin :refs/heads/chore/post-release-v0.2.1
git -C "$w" branch -q -D chore/post-release-v0.2.1
assert_rc "train mode: still refused" 3 bash "$POST" --repo "$w" --version v0.2.1 --mode train

# A fix made on main alone is never dropped: refused, named.
git -C "$w" branch -q -D chore/post-release-v0.2.1 2>/dev/null
git -C "$w" switch -q develop
printf 'dev\n' >"$w/x.txt"; git -C "$w" add x.txt; git -C "$w" commit -q -m "feat: x on develop"; git -C "$w" push -q origin develop
git -C "$w" switch -q main
printf 'main\n' >"$w/x.txt"; git -C "$w" add x.txt; git -C "$w" commit -q -m "fix: x on main only"
git -C "$w" tag -a v0.2.2 -m v0.2.2
git -C "$w" push -q origin main --tags
git -C "$w" switch -q develop
out="$(bash "$POST" --repo "$w" --version v0.2.2 --mode hotfix 2>/dev/null)"; rc=$?
assert_eq "main-only fix: exit 3" 3 "$rc"
assert_contains "main-only fix: named" "$(git -C "$w" rev-parse --short=12 v0.2.2^{commit})" "$out"

finish
