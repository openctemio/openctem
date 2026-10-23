#!/usr/bin/env bash
# Self-test of upgrade-test.sh's choice of the release to upgrade from, and of
# its refusals, on throwaway git repositories (no database needed).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

check() { # name want got
  if [ "$2" != "$3" ]; then echo "FAIL: $1 (want '$2', got '$3')"; fails=$((fails + 1)); else echo "ok: $1"; fi
}

repo="$tmp/repo"
mkdir -p "$repo/.github/scripts"
cp "$here/upgrade-test.sh" "$repo/.github/scripts/"
git -C "$repo" init -q -b develop
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.invalid
git -C "$repo" config commit.gpgsign false
git -C "$repo" config tag.gpgsign false
c() { echo "$1" >>"$repo/f"; git -C "$repo" add -A; git -C "$repo" commit -q -m "$1"; }
prev() { bash "$repo/.github/scripts/upgrade-test.sh" --print-prev-tag; }

c one
git -C "$repo" tag v0.9.0
c two
git -C "$repo" tag v0.10.0
c three
check "the newest tag before HEAD" "v0.10.0" "$(prev)"

# Version order, not alphabetical: v0.10.0 is newer than v0.9.0.
check "versions sort numerically" "v0.10.0" "$(prev)"

# A tag on HEAD itself is the release being built; start from the one before.
git -C "$repo" tag v0.11.0
check "a tag on HEAD is skipped" "v0.10.0" "$(prev)"

# Pre-release style tags and non-release tags are not releases.
git -C "$repo" tag ui/v9.9.9
git -C "$repo" tag nightly
check "tags that are not vX.Y.Z releases are ignored" "v0.10.0" "$(prev)"

# A tag on another branch is not part of this history.
git -C "$repo" checkout -q -b other v0.9.0
c side
git -C "$repo" tag v0.9.1
git -C "$repo" checkout -q develop
check "a tag not reachable from HEAD is ignored" "v0.10.0" "$(prev)"

# No tag at all is an error, not an empty upgrade.
empty="$tmp/empty"
mkdir -p "$empty/.github/scripts"
cp "$here/upgrade-test.sh" "$empty/.github/scripts/"
git -C "$empty" init -q -b develop
git -C "$empty" config user.name test
git -C "$empty" config user.email test@example.invalid
git -C "$empty" config commit.gpgsign false
echo x >"$empty/f"
git -C "$empty" add -A
git -C "$empty" commit -q -m init
set +e
out="$(SUPER_URL=x MIGRATOR_URL=x APP_ROLE_URL=x bash "$empty/.github/scripts/upgrade-test.sh" 2>&1)"
rc=$?
set -e
check "no release tag fails" "1" "$rc"
case "$out" in *"no previous release tag"*) echo "ok: message names the cause";; *) echo "FAIL: message: $out"; fails=$((fails + 1));; esac

# An unknown --prev is an error.
set +e
out="$(SUPER_URL=x MIGRATOR_URL=x APP_ROLE_URL=x bash "$repo/.github/scripts/upgrade-test.sh" --prev v7.7.7 2>&1)"
rc=$?
set -e
check "an unknown --prev fails" "1" "$rc"
case "$out" in *"v7.7.7 is not a tag"*) echo "ok: message names the tag";; *) echo "FAIL: message: $out"; fails=$((fails + 1));; esac

# The database settings are required.
set +e
out="$(env -u SUPER_URL -u MIGRATOR_URL -u APP_ROLE_URL bash "$repo/.github/scripts/upgrade-test.sh" 2>&1)"
rc=$?
set -e
check "missing database settings fail" "1" "$rc"
case "$out" in *"SUPER_URL is required"*) echo "ok: message names the variable";; *) echo "FAIL: message: $out"; fails=$((fails + 1));; esac

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "upgrade-test self-test passed"
