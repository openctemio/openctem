#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Tests for feed-components.sh with stub gh and docker on PATH.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
FC="$RELEASE_DIR/feed-components.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# gh stub: `release list -R <repo> ...` prints $tmp/releases/<repo name>.json.
cat >"$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
repo=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-R" ]]; then repo="$2"; shift; fi
  shift
done
f="$STUB_DIR/releases/${repo#openctemio/}.json"
[[ -f "$f" ]] || { echo "no such repo $repo" >&2; exit 1; }
cat "$f"
STUB
# docker stub: `buildx imagetools inspect <image:tag> ...` prints a manifest
# when $tmp/images/<image:tag with / and : as _> holds a digest.
cat >"$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
ref="$4"
f="$STUB_DIR/images/$(tr '/:' '__' <<<"$ref")"
[[ -f "$f" ]] || { echo "not found: $ref" >&2; exit 1; }
printf '{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s","size":1}\n' "$(cat "$f")"
STUB
chmod +x "$tmp/bin/gh" "$tmp/bin/docker"
mkdir -p "$tmp/releases" "$tmp/images"
export STUB_DIR="$tmp" PATH="$tmp/bin:$PATH" GH_RETRY_ATTEMPTS=1

d1="sha256:$(printf 'a%.0s' {1..64})"
d2="sha256:$(printf 'b%.0s' {1..64})"
cat >"$tmp/releases/sensor.json" <<'EOF'
[{"tagName":"v0.23.10","publishedAt":"2026-10-17T10:00:00Z"},
 {"tagName":"v0.23.9","publishedAt":"2026-10-16T10:00:00Z"},
 {"tagName":"sensor/v9.9.9","publishedAt":"2026-10-18T10:00:00Z"},
 {"tagName":"v0.23.2","publishedAt":"2026-10-15T10:00:00Z"}]
EOF
cat >"$tmp/releases/sdk-go.json" <<'EOF'
[{"tagName":"v0.34.0","publishedAt":"2026-10-15T17:44:37Z"},{"tagName":"v0.33.0","publishedAt":"2026-10-14T19:12:46Z"}]
EOF
# v0.23.10 has no image yet: v0.23.9 is chosen (semver order, not text order).
echo "$d1" >"$tmp/images/ghcr.io_openctemio_sensor_v0.23.9"
echo "$d2" >"$tmp/images/ghcr.io_openctemio_sensor_v0.23.2"

list="sensor openctemio/sensor ghcr.io/openctemio/sensor
sdk openctemio/sdk-go -"
out="$(printf '%s\n' "$list" | bash "$FC" 2>/dev/null)"; rc=$?
assert_eq "resolves: exit 0" 0 "$rc"
assert_eq "sensor: newest release with a published image" "v0.23.9" "$(jq -r '.[] | select(.component=="sensor") | .version' <<<"$out")"
assert_eq "sensor: its digest" "$d1" "$(jq -r '.[] | select(.component=="sensor") | .digest' <<<"$out")"
assert_eq "sensor: notes link" "https://github.com/openctemio/sensor/releases/tag/v0.23.9" "$(jq -r '.[] | select(.component=="sensor") | .notes_url' <<<"$out")"
assert_eq "sensor: published_at" "2026-10-16T10:00:00Z" "$(jq -r '.[] | select(.component=="sensor") | .published_at' <<<"$out")"
assert_eq "sdk: newest release" "v0.34.0" "$(jq -r '.[] | select(.component=="sdk") | .version' <<<"$out")"
assert_eq "sdk: no digest key" "false" "$(jq -r '.[] | select(.component=="sdk") | has("digest")' <<<"$out")"

# Only the newest FEED_CANDIDATES releases are tried.
out="$(printf '%s\n' "$list" | FEED_CANDIDATES=1 bash "$FC" 2>&1)"; rc=$?
assert_eq "no image within the candidates: exit 1" 1 "$rc"
assert_contains "no image within the candidates: says which" "no usable release of openctemio/sensor" "$out"

# A repository that cannot be read fails the run (never a feed without it).
out="$(printf 'connector-x openctemio/connector-x ghcr.io/openctemio/connector-x\n' | bash "$FC" 2>&1)"; rc=$?
assert_eq "unreadable repository: fails" 1 "$rc"

# Malformed lines and foreign repositories are refused.
for line in "Sensor openctemio/sensor -" "sensor someone/sensor -" "sensor openctemio/sensor" "sensor openctemio/sensor - extra"; do
  out="$(printf '%s\n' "$line" | bash "$FC" 2>&1)"; rc=$?
  assert_eq "refused line: $line" 1 "$rc"
done

# An empty list is an error.
out="$(printf '' | bash "$FC" 2>&1)"; rc=$?
assert_eq "empty list: fails" 1 "$rc"

finish
