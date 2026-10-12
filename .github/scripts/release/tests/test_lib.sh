#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Tests for lib.sh: version rules, bump kinds, the versions.yaml reader/writer.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
# shellcheck source=../lib.sh
source "$RELEASE_DIR/lib.sh"

# --- rel_is_version ----------------------------------------------------------
assert_rc "v1.2.3 is a version" 0 rel_is_version v1.2.3
assert_rc "v0.10.0 is a version" 0 rel_is_version v0.10.0
assert_rc "no leading v" 1 rel_is_version 1.2.3
assert_rc "pre-release is not a release" 1 rel_is_version v1.2.3-rc.1
assert_rc "dev is not a release" 1 rel_is_version v1.2.3-dev
assert_rc "leading zero" 1 rel_is_version v1.02.3
assert_rc "empty" 1 rel_is_version ""

# --- rel_version_gt ------------------------------------------------------------
assert_rc "0.10.0 > 0.9.0 (numeric, not lexical)" 0 rel_version_gt v0.10.0 v0.9.0
assert_rc "0.9.0 > 0.10.0 is false" 1 rel_version_gt v0.9.0 v0.10.0
assert_rc "equal is not greater" 1 rel_version_gt v0.9.0 v0.9.0

# --- rel_bump_kind -------------------------------------------------------------
kind() { printf '%b' "$1" | rel_bump_kind; }
RS=$'\x1e'
assert_eq "no commits" none "$(printf '' | rel_bump_kind)"
assert_eq "fix only" patch "$(kind "fix(api): a${RS}docs: b${RS}")"
assert_eq "deps and chores are patch" patch "$(kind "deps: bump x${RS}chore: y${RS}")"
assert_eq "non-conventional is patch" patch "$(kind "Merge branch x${RS}")"
assert_eq "feat wins over fix" feat "$(kind "fix: a${RS}feat(web): b${RS}")"
assert_eq "bang subject is breaking" breaking "$(kind "feat: a${RS}fix(api)!: b${RS}")"
assert_eq "bang without scope" breaking "$(kind "chore!: drop x${RS}")"
assert_eq "BREAKING CHANGE footer" breaking "$(kind "fix: a\n\nbody\nBREAKING CHANGE: gone${RS}")"
assert_eq "BREAKING-CHANGE footer" breaking "$(kind "fix: a\n\nBREAKING-CHANGE: gone${RS}")"
assert_eq "footer word in prose is not breaking" patch "$(kind "fix: a\n\nthis is not a BREAKING CHANGE: really${RS}")"
assert_eq "feat in body is not feat" patch "$(kind "fix: a\n\nfeat: nope${RS}")"
assert_eq "featured is not feat" patch "$(kind "featured: x${RS}")"

# --- rel_next_version ----------------------------------------------------------
assert_eq "0.x breaking bumps minor" v0.9.0 "$(rel_next_version v0.8.0 breaking)"
assert_eq "0.x feat bumps minor" v0.9.0 "$(rel_next_version v0.8.3 feat)"
assert_eq "0.x patch" v0.8.4 "$(rel_next_version v0.8.3 patch)"
assert_eq "1.x breaking bumps major" v2.0.0 "$(rel_next_version v1.4.2 breaking)"
assert_eq "1.x feat bumps minor" v1.5.0 "$(rel_next_version v1.4.2 feat)"
assert_eq "1.x patch" v1.4.3 "$(rel_next_version v1.4.2 patch)"
assert_rc "none: nothing to release" 3 rel_next_version v1.4.2 none
assert_rc "bad base" 2 rel_next_version 1.4.2 patch

# --- rel_latest_tag (version sort, never describe) ------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
new_repo "$tmp/r"
commit "$tmp/r" "first"
git -C "$tmp/r" tag v0.9.0
commit "$tmp/r" "second"
git -C "$tmp/r" tag v0.10.0
git -C "$tmp/r" tag v0.11.0-rc.1
git -C "$tmp/r" tag ui/v9.9.9
git -C "$tmp/r" tag v1.0
assert_eq "highest by version, ignoring rc, prefixed and malformed tags" v0.10.0 "$(rel_latest_tag "$tmp/r")"
new_repo "$tmp/empty"
commit "$tmp/empty" "x"
assert_eq "no tags" "" "$(rel_latest_tag "$tmp/empty")"

# --- rel_yaml_get / rel_yaml_set --------------------------------------------
y="$tmp/v.yaml"
cat >"$y" <<'YAML'
# comment: not a section
platform:
  release: v0.8.0 # trailing comment
sensor:
  latest: "v0.6.4"
  min: ""
sdk:
  latest: v0.14.0
  min: ""
YAML
assert_eq "plain value, comment stripped" v0.8.0 "$(rel_yaml_get "$y" platform.release)"
assert_eq "quoted value" v0.6.4 "$(rel_yaml_get "$y" sensor.latest)"
assert_eq "empty string" "" "$(rel_yaml_get "$y" sensor.min)"
assert_eq "same key, other section" "" "$(rel_yaml_get "$y" sdk.min)"
assert_rc "missing key fails" 1 rel_yaml_get "$y" sensor.max
assert_rc "missing section fails" 1 rel_yaml_get "$y" chart.version
rel_yaml_set "$y" sdk.min v0.12.0
assert_eq "set writes only its section" "v0.12.0|" "$(rel_yaml_get "$y" sdk.min)|$(rel_yaml_get "$y" sensor.min)"
rel_yaml_set "$y" platform.release v0.9.0
assert_eq "set replaces the trailing comment too" "  release: v0.9.0" "$(grep 'release:' "$y")"
rel_yaml_set "$y" sdk.min ""
assert_eq "set empty writes \"\"" '  min: ""' "$(sed -n '/^sdk:/,$p' "$y" | grep 'min:')"
assert_contains "comments kept" "# comment: not a section" "$(cat "$y")"
assert_rc "set unknown key fails" 1 rel_yaml_set "$y" sdk.nope v1.0.0

finish
