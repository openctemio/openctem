#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Tests for sync-versions.sh against a miniature checkout, then against the
# real repository (which must be in sync).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
SYNC="$RELEASE_DIR/sync-versions.sh"
# shellcheck source=../lib.sh
source "$RELEASE_DIR/lib.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# changed_files DIR: the files a sync changed (the fixture is committed first).
changed_files() {
  git -C "$1" add -A >/dev/null
  git -C "$1" diff --cached --name-only HEAD
}
# committed_fixture DIR: a version fixture as a git checkout with one commit.
committed_fixture() {
  version_fixture "$1"
  new_repo "$1"
  git -C "$1" add -A
  git -C "$1" commit -q -m fixture
}

# In sync.
version_fixture "$tmp/ok"
out="$(bash "$SYNC" --check --root "$tmp/ok" 2>&1)"; rc=$?
assert_eq "in sync: exit 0" 0 "$rc"
assert_contains "in sync: says so" "consumers agree" "$out"

# Drift is reported, not fixed, by --check.
version_fixture "$tmp/drift"
sed -i 's/SENSOR_VERSION:-v0.6.4/SENSOR_VERSION:-v0.7.0/' "$tmp/drift/api/deploy/docker-compose.sensor.yml"
sed -i 's/latest: v0.6.4/latest: v0.6.3/' "$tmp/drift/api/internal/versions/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/drift" 2>&1)"; rc=$?
assert_eq "drift: exit 1" 1 "$rc"
assert_contains "drift: names the compose default" "docker-compose.sensor.yml: sensor.latest default is 'v0.7.0', versions.yaml says 'v0.6.4'" "$out"
assert_contains "drift: names the embedded copy" "api/internal/versions/versions.yaml: differs from versions.yaml" "$out"
assert_contains "--check changes nothing" "latest: v0.6.3" "$(cat "$tmp/drift/api/internal/versions/versions.yaml")"

# Without --check it rewrites the consumers, and then --check passes.
bash "$SYNC" --root "$tmp/drift" >/dev/null 2>&1
assert_rc "after sync: in sync" 0 bash "$SYNC" --check --root "$tmp/drift"
assert_eq "sync restored the embedded copy" "$(cat "$tmp/drift/versions.yaml")" "$(cat "$tmp/drift/api/internal/versions/versions.yaml")"

# A missing embedded copy is written.
version_fixture "$tmp/noembed"
rm -f "$tmp/noembed/api/internal/versions/versions.yaml"
assert_rc "no embedded copy: --check fails" 1 bash "$SYNC" --check --root "$tmp/noembed"
bash "$SYNC" --root "$tmp/noembed" >/dev/null 2>&1
assert_rc "no embedded copy: sync writes it" 0 bash "$SYNC" --check --root "$tmp/noembed"

# Moving the scanning sensor's built-in release (optional, at platform release
# time; a sensor release itself needs no change here, the instances learn it
# from the release feed) changes YAML only: versions.yaml, the API's embedded
# copy and the bundled sensor's compose default, never a Go file.
committed_fixture "$tmp/sensorbump"
rel_yaml_set "$tmp/sensorbump/versions.yaml" sensor.latest v0.7.0
bash "$SYNC" --root "$tmp/sensorbump" >/dev/null 2>&1
assert_eq "sensor bump: the manifest, its embedded copy and the bundled sensor default change" \
  "$(printf 'api/deploy/docker-compose.sensor.yml\napi/internal/versions/versions.yaml\nversions.yaml')" "$(changed_files "$tmp/sensorbump")"
assert_contains "sensor bump: bundled sensor default follows" "SENSOR_VERSION:-v0.7.0}" "$(cat "$tmp/sensorbump/api/deploy/docker-compose.sensor.yml")"
assert_contains "sensor bump: embedded copy follows" "latest: v0.7.0" "$(cat "$tmp/sensorbump/api/internal/versions/versions.yaml")"
assert_rc "sensor bump: in sync" 0 bash "$SYNC" --check --root "$tmp/sensorbump"

# The same for any other product, and for the SDK (compatibility changes:
# a minimum, an advisory).
committed_fixture "$tmp/otherbump"
rel_yaml_set "$tmp/otherbump/versions.yaml" connector-tenable.latest v0.2.0
rel_yaml_set "$tmp/otherbump/versions.yaml" connector-tenable.min v0.1.0
rel_yaml_set "$tmp/otherbump/versions.yaml" sdk.latest v0.15.0
rel_yaml_set "$tmp/otherbump/versions.yaml" sdk.advisories "v0.13.0 v0.13.1"
bash "$SYNC" --root "$tmp/otherbump" >/dev/null 2>&1
assert_eq "connector + SDK bump: only YAML changes" \
  "$(printf 'api/internal/versions/versions.yaml\nversions.yaml')" "$(changed_files "$tmp/otherbump")"
assert_rc "connector + SDK bump: in sync" 0 bash "$SYNC" --check --root "$tmp/otherbump"
assert_eq "no .go file anywhere in the fixture" "" "$(find "$tmp/otherbump" -name '*.go' -print)"

# The CI runner release line (ci.latest) drives the console's CI_RELEASE; drift
# is caught and fixed.
version_fixture "$tmp/ci"
sed -i "s/CI_RELEASE = 'v0.2.0'/CI_RELEASE = 'v0.1.0'/" "$tmp/ci/web/src/features/ci-runners/lib/ci.ts"
out="$(bash "$SYNC" --check --root "$tmp/ci" 2>&1)"; rc=$?
assert_eq "ci drift: exit 1" 1 "$rc"
assert_contains "ci drift: names the console pin" "ci.ts: ci.latest default is 'v0.1.0', versions.yaml says 'v0.2.0'" "$out"
sed -i 's/latest: v0.2.0/latest: v0.3.0/' "$tmp/ci/versions.yaml"
bash "$SYNC" --root "$tmp/ci" >/dev/null 2>&1
assert_contains "ci bump: console pin" "CI_RELEASE = 'v0.3.0'" "$(cat "$tmp/ci/web/src/features/ci-runners/lib/ci.ts")"

# Invariants that sync cannot fix.
version_fixture "$tmp/pkg"
sed -i 's/"version": "0.0.0"/"version": "0.2.0"/' "$tmp/pkg/web/package.json"
out="$(bash "$SYNC" --check --root "$tmp/pkg" 2>&1)"; rc=$?
assert_eq "package.json version: exit 1" 1 "$rc"
assert_contains "package.json version: explained" "web/package.json: version is '0.2.0'" "$out"

version_fixture "$tmp/bad"
sed -i 's/latest: v0.14.0/latest: 0.14/' "$tmp/bad/versions.yaml"
sed -i '0,/^  min: ""$/s//  min: v1/' "$tmp/bad/versions.yaml"
sed -i 's/advisories: ""/advisories: "v0.1.0 nope"/' "$tmp/bad/versions.yaml"
sed -i '/^  image: ghcr.io\/openctemio\/connector-tenable$/d' "$tmp/bad/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/bad" 2>&1)"; rc=$?
assert_eq "bad manifest: exit 1" 1 "$rc"
assert_contains "not a version" "sdk.latest '0.14' is not vX.Y.Z" "$out"
assert_contains "optional key still validated" "sensor.min 'v1' is not vX.Y.Z" "$out"
assert_contains "advisory not a version" "sdk.advisories 'nope' is not vX.Y.Z" "$out"
assert_contains "product key missing" "connector-tenable.image is missing" "$out"

version_fixture "$tmp/nosensor"
sed -i 's/^sensor:$/scanner:/' "$tmp/nosensor/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/nosensor" 2>&1)"
assert_contains "the scanning sensor section is required" "the scanning sensor section (sensor:) is missing" "$out"

# The platform version is the git tag: no platform or chart section, and
# nothing in compose or .env.example repeats a version of the platform.
version_fixture "$tmp/platform"
printf 'platform:\n  release: v0.8.0\n' >>"$tmp/platform/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/platform" 2>&1)"; rc=$?
assert_eq "platform section: exit 1" 1 "$rc"
assert_contains "platform section: explained" "the 'platform' section is gone" "$out"
version_fixture "$tmp/chart"
printf 'chart:\n  version: 0.4.1\n' >>"$tmp/chart/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/chart" 2>&1)"
assert_contains "chart section: explained" "the 'chart' section is gone" "$out"

# api/deploy/VERSION must not name a version newer than the newest tag...
version_fixture "$tmp/tags"
new_repo "$tmp/tags"
commit "$tmp/tags" "x"
git -C "$tmp/tags" tag v0.8.0
assert_rc "no VERSION file on develop" 0 bash "$SYNC" --check --root "$tmp/tags"
printf 'v0.8.0\n' >"$tmp/tags/api/deploy/VERSION"
assert_rc "VERSION == newest tag" 0 bash "$SYNC" --check --root "$tmp/tags"
printf 'v0.9.0\n' >"$tmp/tags/api/deploy/VERSION"
out="$(bash "$SYNC" --check --root "$tmp/tags" 2>&1)"
assert_contains "VERSION newer than any tag" "v0.9.0 is newer than the newest tag v0.8.0" "$out"
# ...except on the release branch of exactly that version.
assert_rc "release branch of v0.9.0 may say v0.9.0" 0 bash "$SYNC" --check --root "$tmp/tags" --release v0.9.0
out="$(bash "$SYNC" --check --root "$tmp/tags" --release v0.9.1 2>&1)"; rc=$?
assert_eq "release branch of another version: exit 1" 1 "$rc"
assert_contains "release branch must name its own version" "this is the release branch of v0.9.1" "$out"
printf 'v0.8.0\n' >"$tmp/tags/api/deploy/VERSION"
out="$(bash "$SYNC" --check --root "$tmp/tags" --release v0.9.0 2>&1)"; rc=$?
assert_eq "release branch still naming the previous release: exit 1" 1 "$rc"
assert_contains "previous release on a release branch: explained" "api/deploy/VERSION is 'v0.8.0'" "$out"
rm -f "$tmp/tags/api/deploy/VERSION"
out="$(bash "$SYNC" --check --root "$tmp/tags" --release v0.9.0 2>&1)"
assert_contains "release branch without the file: explained" "api/deploy/VERSION is 'missing'" "$out"
assert_rc "bad --release" 2 bash "$SYNC" --check --root "$tmp/tags" --release 0.9.0

# The real repository is checked by the release-tooling "versions" job, which
# knows the branch (a release branch is ahead of the newest tag).

finish
