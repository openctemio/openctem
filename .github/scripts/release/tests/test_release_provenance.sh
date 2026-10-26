#!/usr/bin/env bash
# Tests for ../../release-provenance.sh: a release PR is verified only when it is a
# green develop commit plus the version commit (train), or the last tag plus
# cherry-picks of green develop commits plus the version commit (hotfix).
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
CUT="$RELEASE_DIR/cut-release.sh"
PROV="$RELEASE_DIR/../release-provenance.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scenario "$tmp"
w="$tmp/work"
dev="$(git -C "$w" rev-parse develop)"
export CHECK_RUNS_DIR="$tmp/runs" REQUIRED_CHECKS="API CI OK"
mkdir -p "$CHECK_RUNS_DIR"
green() { echo '[{"name":"API CI OK","status":"completed","conclusion":"success","id":1}]' >"$CHECK_RUNS_DIR/$1.json"; }
red() { echo '[{"name":"API CI OK","status":"completed","conclusion":"failure","id":1}]' >"$CHECK_RUNS_DIR/$1.json"; }

# prov HEAD_REF HEAD_SHA [BASE_REF]: run in the clone as a pull request would.
prov() {
  (cd "$w" && GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF="${3:-main}" HEAD_REF="$1" HEAD_SHA="$2" \
    HEAD_REPO=o/r BASE_REPO=o/r bash "$PROV" 2>&1)
}

# --- train ---------------------------------------------------------------------
out="$(bash "$CUT" --repo "$w" --version v0.3.0 --sha "$dev" --push 2>/dev/null)"
head="$(sed -n 's/^HEAD=//p' <<<"$out")"
green "$dev"
out="$(prov release/v0.3.0 "$head")"; rc=$?
assert_eq "train: verified ($out)" 0 "$rc"
assert_contains "train: names the develop commit" "${dev:0:12}" "$out"

red "$dev"
out="$(prov release/v0.3.0 "$head")"; rc=$?
assert_eq "train: a red develop commit is not verified" 1 "$rc"
rm "$CHECK_RUNS_DIR/$dev.json"
assert_rc "train: a develop commit with no recorded checks is not verified" 1 prov release/v0.3.0 "$head"
green "$dev"

assert_rc "ordinary PR into develop: silent no" 1 prov feature/x "$head" develop
assert_rc "head branch that is not release/vX.Y.Z" 1 prov release/next "$head"
out="$(cd "$w" && GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF=main HEAD_REF=release/v0.3.0 HEAD_SHA="$head" HEAD_REPO=fork/r BASE_REPO=o/r bash "$PROV" 2>&1)"; rc=$?
assert_eq "a fork's release branch is not verified" 1 "$rc"
assert_eq "wrong version in the branch name" 1 "$(prov release/v0.3.1 "$head" >/dev/null; echo $?)"

# An extra change hidden in the version commit: not verified.
git -C "$w" switch -q -c evil "$head^1"
echo x >>"$w/api/internal/app.go" 2>/dev/null || { mkdir -p "$w/api/internal"; echo x >"$w/api/internal/app.go"; }
git -C "$w" add -A; git -C "$w" commit -q --amend --no-edit
v2="$(git -C "$w" rev-parse HEAD)"
git -C "$w" merge -q -s ours --no-edit origin/main >/dev/null
evil="$(git -C "$w" rev-parse HEAD)"
out="$(prov release/v0.3.0 "$evil")"; rc=$?
assert_eq "train: a code change in the version commit is not verified" 1 "$rc"
assert_contains "train: names the file" "api/internal/app.go" "$out"

# A commit added on top of the release head: not a release shape.
git -C "$w" switch -q -c extra "$head"
commit "$w" "fix: sneaked in" api/internal/x.go
extra="$(git -C "$w" rev-parse HEAD)"
assert_eq "train: an extra commit on top is not verified" 1 "$(prov release/v0.3.0 "$extra" >/dev/null; echo $?)"

# Develop moved on and the release was cut from a commit that is not on develop.
git -C "$w" switch -q -c offdev "$dev"
commit "$w" "feat: never merged" api/internal/y.go
off="$(git -C "$w" rev-parse HEAD)"
green "$off"
git -C "$w" push -q origin offdev
git -C "$w" branch -q -D release/v0.3.0 2>/dev/null; git -C "$w" push -q origin :refs/heads/release/v0.3.0
out="$(bash "$CUT" --repo "$w" --version v0.3.0 --sha "$off" 2>/dev/null)"
offhead="$(sed -n 's/^HEAD=//p' <<<"$out")"
assert_eq "train: a green commit that is not on develop is not verified" 1 "$(prov release/v0.3.0 "$offhead" >/dev/null; echo $?)"
git -C "$w" switch -q develop
git -C "$w" branch -q -D release/v0.3.0 2>/dev/null

# --- hotfix --------------------------------------------------------------------
fix="$(git -C "$w" log --format=%H --grep '^fix(api): after release' -n 1 develop)"
out="$(bash "$CUT" --repo "$w" --version v0.2.1 --mode hotfix --picks "$fix" 2>/dev/null)"
hf="$(sed -n 's/^HEAD=//p' <<<"$out")"
green "$fix"; green "$dev"
out="$(prov release/v0.2.1 "$hf")"; rc=$?
assert_eq "hotfix: verified ($out)" 0 "$rc"
assert_contains "hotfix: counts the pick" "1 cherry-pick" "$out"
red "$dev"; red "$fix"
assert_eq "hotfix: a red develop commit is not verified" 1 "$(prov release/v0.2.1 "$hf" >/dev/null; echo $?)"
green "$dev"; green "$fix"

# A pick whose patch differs from the develop commit it claims.
git -C "$w" switch -q -c forged "v0.2.0^{commit}"
# A forged pick (different patch, same -x line), then the real version commit's changes.
echo "different" >"$w/forged.txt"; git -C "$w" add forged.txt
git -C "$w" commit -q -m "fix: forged

(cherry picked from commit $fix)"
git -C "$w" checkout -q "$hf" -- versions.yaml api
git -C "$w" commit -q -m "chore(release): versions.yaml platform.release = v0.2.1"
forged="$(git -C "$w" rev-parse HEAD)"
out="$(prov release/v0.2.1 "$forged")"; rc=$?
assert_eq "hotfix: a pick that differs from its develop commit is not verified" 1 "$rc"
git -C "$w" switch -q develop

finish
