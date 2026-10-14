#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Tests for sync-versions.sh against a miniature checkout, then against the
# real repository (which must be in sync).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
SYNC="$RELEASE_DIR/sync-versions.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT


# In sync.
version_fixture "$tmp/ok"
out="$(bash "$SYNC" --check --root "$tmp/ok" 2>&1)"; rc=$?
assert_eq "in sync: exit 0" 0 "$rc"
assert_contains "in sync: says so" "consumers agree" "$out"

# Drift is reported, not fixed, by --check.
version_fixture "$tmp/drift"
sed -i 's/v0.6.4"/v0.4.2"/' "$tmp/drift/api/internal/config/config.go"
sed -i 's/SENSOR_SDK_MIN_VERSION:-}/SENSOR_SDK_MIN_VERSION:-v0.1.0}/' "$tmp/drift/api/deploy/docker-compose.yml"
out="$(bash "$SYNC" --check --root "$tmp/drift" 2>&1)"; rc=$?
assert_eq "drift: exit 1" 1 "$rc"
assert_contains "drift: names the Go default" "config.go: sensor.latest default is 'v0.4.2', versions.yaml says 'v0.6.4'" "$out"
assert_contains "drift: names the compose default" "docker-compose.yml: sdk.min default is 'v0.1.0', versions.yaml says ''" "$out"
assert_contains "--check changes nothing" 'v0.4.2"' "$(cat "$tmp/drift/api/internal/config/config.go")"

# Without --check it rewrites the consumers, and then --check passes.
bash "$SYNC" --root "$tmp/drift" >/dev/null 2>&1
assert_rc "after sync: in sync" 0 bash "$SYNC" --check --root "$tmp/drift"
assert_contains "sync restored the Go default" 'DefaultSensorLatestVersion = "v0.6.4"' "$(cat "$tmp/drift/api/internal/config/config.go")"
# shellcheck disable=SC2016 # a literal compose expression
assert_contains "sync kept the closing brace" 'SENSOR_SDK_MIN_VERSION: ${SENSOR_SDK_MIN_VERSION:-}' "$(cat "$tmp/drift/api/deploy/docker-compose.yml")"

# A release bump: change versions.yaml, sync, every consumer follows.
version_fixture "$tmp/bump"
sed -i 's/release: v0.8.0/release: v0.9.0/; s/latest: v0.6.4/latest: v0.7.0/' "$tmp/bump/versions.yaml"
bash "$SYNC" --root "$tmp/bump" >/dev/null 2>&1
assert_eq "bump: .env.example" "OPENCTEM_VERSION=v0.9.0" "$(head -n 1 "$tmp/bump/api/deploy/.env.example")"
assert_contains "bump: compose default" "OPENCTEM_VERSION:-v0.9.0}}" "$(cat "$tmp/bump/api/deploy/docker-compose.yml")"
assert_contains "bump: sensor image" 'sensor:v0.7.0"' "$(cat "$tmp/bump/api/internal/infra/http/handler/sensor_handler.go")"
assert_contains "bump: other lines untouched" "OTHER=1" "$(cat "$tmp/bump/api/deploy/.env.example")"

# The CI runner release line (ci.latest) drives the Go default and the
# console's CI_RELEASE; drift in either is caught and fixed.
version_fixture "$tmp/ci"
sed -i "s/CI_RELEASE = 'v0.2.0'/CI_RELEASE = 'v0.1.0'/" "$tmp/ci/web/src/features/ci-runners/lib/ci.ts"
out="$(bash "$SYNC" --check --root "$tmp/ci" 2>&1)"; rc=$?
assert_eq "ci drift: exit 1" 1 "$rc"
assert_contains "ci drift: names the console pin" "ci.ts: ci.latest default is 'v0.1.0', versions.yaml says 'v0.2.0'" "$out"
sed -i 's/latest: v0.2.0/latest: v0.3.0/' "$tmp/ci/versions.yaml"
bash "$SYNC" --root "$tmp/ci" >/dev/null 2>&1
assert_contains "ci bump: console pin" "CI_RELEASE = 'v0.3.0'" "$(cat "$tmp/ci/web/src/features/ci-runners/lib/ci.ts")"
assert_contains "ci bump: Go default" 'DefaultCIRunnerLatestVersion = "v0.3.0"' "$(cat "$tmp/ci/api/internal/config/config.go")"

# Invariants that sync cannot fix.
version_fixture "$tmp/pkg"
sed -i 's/"version": "0.0.0"/"version": "0.2.0"/' "$tmp/pkg/web/package.json"
out="$(bash "$SYNC" --check --root "$tmp/pkg" 2>&1)"; rc=$?
assert_eq "package.json version: exit 1" 1 "$rc"
assert_contains "package.json version: explained" "web/package.json: version is '0.2.0'" "$out"

version_fixture "$tmp/bad"
sed -i 's/latest: v0.14.0/latest: 0.14/' "$tmp/bad/versions.yaml"
sed -i 's/^  min: ""$/  min: v1/' "$tmp/bad/versions.yaml"
sed -i '/^platform:/,/^sensor:/d' "$tmp/bad/versions.yaml"
printf 'sensor:\n' | cat - "$tmp/bad/versions.yaml" >"$tmp/bad/v" && mv "$tmp/bad/v" "$tmp/bad/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/bad" 2>&1)"; rc=$?
assert_eq "bad manifest: exit 1" 1 "$rc"
assert_contains "missing key" "platform.release is missing" "$out"
assert_contains "not a version" "sdk.latest '0.14' is not vX.Y.Z" "$out"
assert_contains "optional key still validated" "sensor.min 'v1' is not vX.Y.Z" "$out"

version_fixture "$tmp/moved"
echo 'var DefaultSensorLatestVersion = "v0.6.4"' >"$tmp/moved/api/internal/config/config.go"
out="$(bash "$SYNC" --check --root "$tmp/moved" 2>&1)"; rc=$?
assert_eq "consumer changed shape: exit 1" 1 "$rc"
assert_contains "consumer changed shape: explained" "no default for sensor.latest matches" "$out"

# platform.release must name a tag that exists (when the checkout has tags).
version_fixture "$tmp/tags"
new_repo "$tmp/tags"
commit "$tmp/tags" "x"
git -C "$tmp/tags" tag v0.8.0
assert_rc "release == newest tag" 0 bash "$SYNC" --check --root "$tmp/tags"
sed -i 's/release: v0.8.0/release: v0.9.0/' "$tmp/tags/versions.yaml"
sed -i 's/=v0.8.0/=v0.9.0/' "$tmp/tags/api/deploy/.env.example"
sed -i 's/OPENCTEM_VERSION:-v0.8.0/OPENCTEM_VERSION:-v0.9.0/' "$tmp/tags/api/deploy/docker-compose.yml"
out="$(bash "$SYNC" --check --root "$tmp/tags" 2>&1)"
assert_contains "release newer than any tag" "platform.release v0.9.0 is newer than the newest tag v0.8.0" "$out"
# ...except on the release branch of exactly that version.
sed -i 's/OPENCTEM_VERSION:-v0.8.0/OPENCTEM_VERSION:-v0.9.0/' "$tmp/tags/api/deploy/docker-compose.job-signer.yml"
assert_rc "release branch of v0.9.0 may say v0.9.0" 0 bash "$SYNC" --check --root "$tmp/tags" --release v0.9.0
out="$(bash "$SYNC" --check --root "$tmp/tags" --release v0.9.1 2>&1)"; rc=$?
assert_eq "release branch of another version: exit 1" 1 "$rc"
assert_contains "release branch must name its own version" "this is the release branch of v0.9.1" "$out"
sed -i 's/release: v0.9.0/release: v0.8.0/' "$tmp/tags/versions.yaml"
bash "$SYNC" --root "$tmp/tags" >/dev/null 2>&1
out="$(bash "$SYNC" --check --root "$tmp/tags" --release v0.9.0 2>&1)"; rc=$?
assert_eq "release branch still naming the previous release: exit 1" 1 "$rc"
assert_contains "previous release on a release branch: explained" "platform.release is 'v0.8.0'" "$out"
assert_rc "bad --release" 2 bash "$SYNC" --check --root "$tmp/tags" --release 0.9.0

# The real repository is checked by the release-tooling "versions" job, which
# knows the branch (a release branch is ahead of the newest tag).

finish
