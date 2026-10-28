#!/usr/bin/env bash
# Tests for the publish half of a train: tag-release.sh after the release PR
# merged, then post-release.sh (the develop follow-up), then helm-bump.sh.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scenario "$tmp"
w="$tmp/work"

# develop carries versions.yaml and its consumers (no platform version in them).
version_fixture "$w"
git -C "$w" add -A
git -C "$w" commit -q -m "chore: versions.yaml" >/dev/null 2>&1 || true
git -C "$w" push -q origin develop
dev="$(git -C "$w" rev-parse develop)"

# Cut and "merge the PR" the way the merge queue does (a merge commit).
cut="$(bash "$RELEASE_DIR/cut-release.sh" --repo "$w" --version v0.3.0 --sha "$dev" --push 2>/dev/null)"
head="$(sed -n 's/^HEAD=//p' <<<"$cut")"
git -C "$w" switch -q main
git -C "$w" pull -q --ff-only origin main
git -C "$w" merge -q --no-ff --no-edit "$head"
git -C "$w" push -q origin main
merge="$(git -C "$w" rev-parse HEAD)"
git -C "$w" switch -q develop

# --- tag-release.sh -------------------------------------------------------------
TAG="$RELEASE_DIR/tag-release.sh"
assert_rc "tree mismatch refused" 1 bash "$TAG" --repo "$w" --version v0.3.0 --commit "$merge" --release-head "$dev~1"
assert_rc "not greater refused" 1 bash "$TAG" --repo "$w" --version v0.2.0 --commit "$merge" --release-head "$head"
git -C "$w" switch -q -c side develop
commit "$w" "chore: side" side.txt
side="$(git -C "$w" rev-parse HEAD)"
git -C "$w" switch -q develop
assert_rc "commit not on main refused" 1 bash "$TAG" --repo "$w" --version v0.3.0 --commit "$side" --release-head "$side"
assert_rc "api/deploy/VERSION names another release: refused" 1 bash "$TAG" --repo "$w" --version v0.4.0 --commit "$merge" --release-head "$head"
out="$(bash "$TAG" --repo "$w" --version v0.3.0 --commit "$merge" --release-head "$head" --push 2>&1)"; rc=$?
assert_eq "tag: exit 0 ($out)" 0 "$rc"
assert_eq "tag: annotated" tag "$(git -C "$w" cat-file -t v0.3.0)"
assert_eq "tag: on the merge commit" "$merge" "$(git -C "$w" rev-parse 'v0.3.0^{commit}')"
assert_contains "tag: pushed" "refs/tags/v0.3.0" "$(git -C "$w" ls-remote --tags origin)"
assert_rc "tag: twice refused" 1 bash "$TAG" --repo "$w" --version v0.3.0 --commit "$merge" --release-head "$head"

# --- post-release.sh ------------------------------------------------------------
# develop moves on after the cut; the follow-up must keep that.
commit "$w" "fix: after the cut" later.txt
git -C "$w" push -q origin develop
POST="$RELEASE_DIR/post-release.sh"
out="$(bash "$POST" --repo "$w" --version v0.3.0 --push 2>"$tmp/err")"; rc=$?
assert_eq "post: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
ph="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_rc "post: the tag is an ancestor of the follow-up" 0 git -C "$w" merge-base --is-ancestor v0.3.0 "$ph"
assert_rc "post: develop's later commit kept" 0 git -C "$w" cat-file -e "$ph:later.txt"
assert_eq "post: no file differs from develop (no version lands on develop)" "" "$(git -C "$w" diff --name-only origin/develop "$ph")"
assert_eq "post: no VERSION file on the follow-up" "" "$(git -C "$w" ls-tree --name-only "$ph" api/deploy/VERSION)"
assert_contains "post: pushed" "refs/heads/chore/post-release-v0.3.0" "$(git -C "$w" ls-remote --heads origin)"
assert_rc "post: branch exists -> refused" 1 bash "$POST" --repo "$w" --version v0.3.0
assert_rc "post: untagged version refused" 1 bash "$POST" --repo "$w" --version v0.9.9

# A hotfix needs no develop follow-up: no branch, exit 0.
git -C "$w" push -q origin :refs/heads/chore/post-release-v0.3.0
git -C "$w" branch -q -D chore/post-release-v0.3.0
out="$(bash "$POST" --repo "$w" --version v0.3.0 --mode hotfix --push 2>/dev/null)"; rc=$?
assert_eq "post hotfix: exit 0" 0 "$rc"
assert_eq "post hotfix: prints no branch" "" "$out"
assert_eq "post hotfix: pushes nothing" "" "$(git -C "$w" ls-remote --heads origin 'chore/post-release-*')"
git -C "$w" branch -q -D chore/post-release-v0.3.0 2>/dev/null || true

# A train whose main carries a file develop never had is refused.
git -C "$w" switch -q main
commit "$w" "fix: made on main only" onlymain.txt
git -C "$w" tag -a v0.3.1 -m v0.3.1
git -C "$w" push -q origin main --tags
git -C "$w" switch -q develop
out="$(bash "$POST" --repo "$w" --version v0.3.1 2>&1)"; rc=$?
assert_eq "post: main-only change refused" 1 "$rc"
assert_contains "post: main-only change explained" "onlymain.txt" "$out"

# --- helm-bump.sh ------------------------------------------------------------------
HB="$RELEASE_DIR/helm-bump.sh"
chart="$tmp/Chart.yaml"
printf 'apiVersion: v2\nname: openctem\n# comment\nversion: 0.10.0\nappVersion: "v0.9.0"\n' >"$chart"
out="$(bash "$HB" --chart "$chart" --app-version v0.9.1)"
assert_contains "patch release -> chart patch" "CHART_VERSION=0.10.1" "$out"
assert_contains "appVersion set" 'appVersion: "v0.9.1"' "$(cat "$chart")"
assert_contains "version set" "version: 0.10.1" "$(cat "$chart")"
assert_contains "comments kept" "# comment" "$(cat "$chart")"
out="$(bash "$HB" --chart "$chart" --app-version v0.10.0)"
assert_contains "minor release -> chart minor" "CHART_VERSION=0.11.0" "$out"
assert_rc "same appVersion -> exit 4" 4 bash "$HB" --chart "$chart" --app-version v0.10.0
assert_rc "bad version" 2 bash "$HB" --chart "$chart" --app-version 0.10.1

finish
