#!/usr/bin/env bash
# testlib.sh: tiny assertion helpers for the release script tests.
# Source it from a test_*.sh, call the assert_* helpers, end with `finish`.
set -uo pipefail

TESTS_RUN=0
TESTS_FAILED=0
export RELEASE_DIR
RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

assert_eq() { # name want got
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$2" != "$3" ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    want: %q\n    got:  %q\n' "$1" "$2" "$3"
  fi
}

assert_contains() { # name needle haystack
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$3" != *"$2"* ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    want to contain: %q\n    got: %s\n' "$1" "$2" "$3"
  fi
}

assert_not_contains() { # name needle haystack
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$3" == *"$2"* ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    must not contain: %q\n    got: %s\n' "$1" "$2" "$3"
  fi
}

assert_rc() { # name want-rc command...
  local name="$1" want="$2" got
  shift 2
  "$@" >/dev/null 2>&1
  got=$?
  assert_eq "$name (exit code)" "$want" "$got"
}

# new_repo DIR: an empty git repository with a deterministic identity.
new_repo() {
  git init -q -b main "$1"
  git -C "$1" config user.name test
  git -C "$1" config user.email test@example.invalid
  git -C "$1" config commit.gpgsign false
  git -C "$1" config tag.gpgsign false
}

# commit DIR MESSAGE [FILE]: commit a change (touches FILE, default "f").
commit() {
  local f="${3:-f}"
  mkdir -p "$(dirname "$1/$f")"
  echo "$2 $RANDOM" >>"$1/$f"
  git -C "$1" add -A
  git -C "$1" commit -q -m "$2"
}

finish() {
  echo "  $TESTS_RUN assertion(s), $TESTS_FAILED failed"
  [[ $TESTS_FAILED -eq 0 ]]
}

# scenario DIR: a bare "origin" and a clone "work" shaped like this repository:
#   main     v0.1.0, then a SQUASHED release of develop (single parent), v0.2.0
#   develop  branched at v0.1.0; after the release it gains a fix, a feature
#            and deletes gone.txt (which main still has)
# Prints nothing; sets nothing. The clone is "$DIR/work", origin "$DIR/origin.git".
scenario() {
  local d="$1" w="$1/work"
  git init -q --bare -b main "$d/origin.git"
  new_repo "$w"
  git -C "$w" remote add origin "$d/origin.git"
  commit "$w" "chore: init" a.txt
  git -C "$w" tag -a v0.1.0 -m v0.1.0
  git -C "$w" switch -q -c develop
  commit "$w" "feat(api): first feature" b.txt
  commit "$w" "fix(web): first fix" c.txt
  commit "$w" "chore: add gone" gone.txt
  # Squash-release develop into main: main gets develop's tree, one parent.
  git -C "$w" switch -q main
  git -C "$w" checkout -q develop -- .
  git -C "$w" commit -q -m "Release v0.2.0 (#1)"
  git -C "$w" tag -a v0.2.0 -m v0.2.0
  git -C "$w" switch -q develop
  commit "$w" "fix(api): after release" d.txt
  git -C "$w" rm -q gone.txt
  git -C "$w" commit -q -m "chore: remove gone"
  git -C "$w" push -q origin main develop --tags
}

# version_fixture DIR: versions.yaml plus every consumer, all in agreement.
version_fixture() {
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
