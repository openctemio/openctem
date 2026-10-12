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

# develop carries versions.yaml and its consumers (platform.release v0.2.0).
version_fixture "$w"
sed -i 's/v0.8.0/v0.2.0/g' "$w/versions.yaml" "$w/api/deploy/.env.example" "$w/api/deploy/docker-compose.yml"
git -C "$w" add -A
git -C "$w" commit -q -m "chore: versions.yaml"
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
out="$(bash "$POST" --repo "$w" --version v0.3.0 --chart-version 0.5.0 --push 2>"$tmp/err")"; rc=$?
assert_eq "post: exit 0 ($(cat "$tmp/err"))" 0 "$rc"
ph="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_rc "post: the tag is an ancestor of the follow-up" 0 git -C "$w" merge-base --is-ancestor v0.3.0 "$ph"
assert_rc "post: develop's later commit kept" 0 git -C "$w" cat-file -e "$ph:later.txt"
assert_contains "post: versions.yaml bumped" "release: v0.3.0" "$(git -C "$w" show "$ph:versions.yaml")"
assert_contains "post: chart bumped" "version: 0.5.0" "$(git -C "$w" show "$ph:versions.yaml")"
assert_contains "post: consumers synced" "OPENCTEM_VERSION=v0.3.0" "$(git -C "$w" show "$ph:api/deploy/.env.example")"
assert_eq "post: only versions files differ from develop" \
  "$(printf 'api/deploy/.env.example\napi/deploy/docker-compose.yml\nversions.yaml')" \
  "$(git -C "$w" diff --name-only origin/develop "$ph")"
assert_contains "post: pushed" "refs/heads/chore/post-release-v0.3.0" "$(git -C "$w" ls-remote --heads origin)"
assert_rc "post: branch exists -> refused" 1 bash "$POST" --repo "$w" --version v0.3.0
assert_rc "post: untagged version refused" 1 bash "$POST" --repo "$w" --version v0.9.9

# Hotfix mode does not merge main back.
git -C "$w" push -q origin :refs/heads/chore/post-release-v0.3.0
git -C "$w" branch -q -D chore/post-release-v0.3.0
out="$(bash "$POST" --repo "$w" --version v0.3.0 --mode hotfix 2>/dev/null)"
ph="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_rc "post hotfix: no merge-back" 1 git -C "$w" merge-base --is-ancestor v0.3.0 "$ph"
assert_contains "post hotfix: still bumps versions.yaml" "release: v0.3.0" "$(git -C "$w" show "$ph:versions.yaml")"

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
