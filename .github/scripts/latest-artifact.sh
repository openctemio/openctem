#!/usr/bin/env bash
# Copies one file out of the newest unexpired artifact of this repository with
# a given name, for data a previous run recorded (test durations). Exit 0 and
# no file when there is none: callers fall back to their default.
#
#   latest-artifact.sh <artifact name> <file inside it> <destination>
#
# Env: REPO (owner/name), GH_TOKEN (actions: read).
#
# Trust: the data only steers load balancing (which shard runs which test
# package or file); it is validated as a JSON object by the caller and a wrong
# one can only unbalance shards, never skip a test. Only runs of non-pull-
# request events upload these artifacts.
set -uo pipefail

name="${1:?artifact name}" file="${2:?file in artifact}" dest="${3:?destination}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
id="$(gh api "repos/${REPO:?}/actions/artifacts?name=${name}&per_page=1" \
  --jq '.artifacts[] | select(.expired | not) | .id' 2>/dev/null | head -1)" || exit 0
[ -n "$id" ] || exit 0
gh api "repos/${REPO}/actions/artifacts/${id}/zip" > "$tmp/a.zip" 2>/dev/null || exit 0
unzip -p "$tmp/a.zip" "$file" > "$tmp/out" 2>/dev/null || exit 0
jq -e 'type == "object" and length > 0' "$tmp/out" >/dev/null 2>&1 || exit 0
cp "$tmp/out" "$dest"
echo "latest-artifact: $name #$id -> $dest ($(jq length "$dest") entries)"
