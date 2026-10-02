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

fixture() { # DIR: a checkout whose consumers all agree with its versions.yaml
  local d="$1"
  mkdir -p "$d/api/deploy" "$d/api/internal/config" "$d/api/internal/infra/http/handler" "$d/web"
  cat >"$d/versions.yaml" <<'YAML'
platform:
  release: v0.8.0
sensor:
  latest: v0.6.4
  min: ""
sdk:
  latest: v0.14.0
  min: ""
chart:
  version: 0.4.1
YAML
  printf 'OPENCTEM_VERSION=v0.8.0\nOTHER=1\n' >"$d/api/deploy/.env.example"
  cat >"$d/api/deploy/docker-compose.yml" <<'YAML'
    image: x:${UI_VERSION:-${OPENCTEM_VERSION:?OPENCTEM_VERSION is required, e.g. v0.8.0}}
      SENSOR_LATEST_VERSION: ${SENSOR_LATEST_VERSION:-v0.6.4}
      SENSOR_MIN_VERSION: ${SENSOR_MIN_VERSION:-}
      SENSOR_SDK_MIN_VERSION: ${SENSOR_SDK_MIN_VERSION:-}
      SENSOR_SDK_LATEST_VERSION: ${SENSOR_SDK_LATEST_VERSION:-v0.14.0}
YAML
  cat >"$d/api/internal/config/config.go" <<'GO'
const DefaultSensorLatestVersion = "v0.6.4"
const DefaultSensorMinVersion = ""
const DefaultSensorSDKLatestVersion = "v0.14.0"
const DefaultSensorSDKMinVersion = ""
GO
  echo 'const DefaultSensorImage = "ghcr.io/openctemio/sensor:v0.6.4"' >"$d/api/internal/infra/http/handler/sensor_handler.go"
  printf '# SENSOR_LATEST_VERSION=v0.6.4\n# SENSOR_SDK_LATEST_VERSION=v0.14.0\n' >"$d/api/.env.example"
  printf '{\n  "name": "w",\n  "version": "0.0.0",\n  "private": true\n}\n' >"$d/web/package.json"
}

# In sync.
fixture "$tmp/ok"
out="$(bash "$SYNC" --check --root "$tmp/ok" 2>&1)"; rc=$?
assert_eq "in sync: exit 0" 0 "$rc"
assert_contains "in sync: says so" "consumers agree" "$out"

# Drift is reported, not fixed, by --check.
fixture "$tmp/drift"
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
fixture "$tmp/bump"
sed -i 's/release: v0.8.0/release: v0.9.0/; s/latest: v0.6.4/latest: v0.7.0/' "$tmp/bump/versions.yaml"
bash "$SYNC" --root "$tmp/bump" >/dev/null 2>&1
assert_eq "bump: .env.example" "OPENCTEM_VERSION=v0.9.0" "$(head -n 1 "$tmp/bump/api/deploy/.env.example")"
assert_contains "bump: compose example" "e.g. v0.9.0}}" "$(cat "$tmp/bump/api/deploy/docker-compose.yml")"
assert_contains "bump: sensor image" 'sensor:v0.7.0"' "$(cat "$tmp/bump/api/internal/infra/http/handler/sensor_handler.go")"
assert_contains "bump: env example comment" "# SENSOR_LATEST_VERSION=v0.7.0" "$(cat "$tmp/bump/api/.env.example")"
assert_contains "bump: other lines untouched" "OTHER=1" "$(cat "$tmp/bump/api/deploy/.env.example")"

# Invariants that sync cannot fix.
fixture "$tmp/pkg"
sed -i 's/"version": "0.0.0"/"version": "0.2.0"/' "$tmp/pkg/web/package.json"
out="$(bash "$SYNC" --check --root "$tmp/pkg" 2>&1)"; rc=$?
assert_eq "package.json version: exit 1" 1 "$rc"
assert_contains "package.json version: explained" "web/package.json: version is '0.2.0'" "$out"

fixture "$tmp/bad"
sed -i 's/latest: v0.14.0/latest: 0.14/' "$tmp/bad/versions.yaml"
sed -i 's/^  min: ""$/  min: v1/' "$tmp/bad/versions.yaml"
sed -i '/^platform:/,/^sensor:/d' "$tmp/bad/versions.yaml"
printf 'sensor:\n' | cat - "$tmp/bad/versions.yaml" >"$tmp/bad/v" && mv "$tmp/bad/v" "$tmp/bad/versions.yaml"
out="$(bash "$SYNC" --check --root "$tmp/bad" 2>&1)"; rc=$?
assert_eq "bad manifest: exit 1" 1 "$rc"
assert_contains "missing key" "platform.release is missing" "$out"
assert_contains "not a version" "sdk.latest '0.14' is not vX.Y.Z" "$out"
assert_contains "optional key still validated" "sensor.min 'v1' is not vX.Y.Z" "$out"

fixture "$tmp/moved"
echo 'var DefaultSensorLatestVersion = "v0.6.4"' >"$tmp/moved/api/internal/config/config.go"
out="$(bash "$SYNC" --check --root "$tmp/moved" 2>&1)"; rc=$?
assert_eq "consumer changed shape: exit 1" 1 "$rc"
assert_contains "consumer changed shape: explained" "no default for sensor.latest matches" "$out"

# platform.release must name a tag that exists (when the checkout has tags).
fixture "$tmp/tags"
new_repo "$tmp/tags"
commit "$tmp/tags" "x"
git -C "$tmp/tags" tag v0.8.0
assert_rc "release == newest tag" 0 bash "$SYNC" --check --root "$tmp/tags"
sed -i 's/release: v0.8.0/release: v0.9.0/' "$tmp/tags/versions.yaml"
sed -i 's/=v0.8.0/=v0.9.0/' "$tmp/tags/api/deploy/.env.example"
sed -i 's/e.g. v0.8.0/e.g. v0.9.0/' "$tmp/tags/api/deploy/docker-compose.yml"
out="$(bash "$SYNC" --check --root "$tmp/tags" 2>&1)"
assert_contains "release newer than any tag" "platform.release v0.9.0 is newer than the newest tag v0.8.0" "$out"

# The real repository.
REPO="$(cd "$RELEASE_DIR/../../.." && pwd)"
out="$(bash "$SYNC" --check --root "$REPO" 2>&1)"; rc=$?
assert_eq "this repository is in sync (run sync-versions.sh): $out" 0 "$rc"

finish
