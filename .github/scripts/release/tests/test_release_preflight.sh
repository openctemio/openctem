#!/usr/bin/env bash
# Tests for ../../release-preflight.sh with a fake `gh` and a throwaway repository.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
PRE="$RELEASE_DIR/../release-preflight.sh"

tmp="$(mktemp -d)"
trap 'find "$tmp" -delete' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
case "$*" in
  *"code-scanning/alerts?ref=refs/heads/develop"*) cat "$DEV_FILE" ;;
  *"code-scanning/alerts?ref=refs/heads/main"*) cat "$MAIN_FILE" ;;
  *"actions/artifacts"*) exit 1 ;;
  *"repos/openctemio/sensor/releases/latest"*) echo "${SENSOR_PUBLISHED:-v0.2.0}" ;;
  *"repos/openctemio/sdk-go/releases/latest"*) echo "v0.5.0" ;;
  *"releases/latest"*) exit 1 ;;
  *) echo "unexpected gh: $*" >&2; exit 2 ;;
esac
GH
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" DEV_FILE="$tmp/dev.json" MAIN_FILE="$tmp/main.json" REPO=o/r

new_repo "$tmp/r"
git -C "$tmp/r" checkout -q -b develop
commit "$tmp/r" "init" a.txt
mig() { mkdir -p "$tmp/r/api/migrations"; : >"$tmp/r/api/migrations/$1_$2.up.sql"; : >"$tmp/r/api/migrations/$1_$2.down.sql"; git -C "$tmp/r" add -A; git -C "$tmp/r" commit -q -m "migration $1"; }
mig 000010 first
git -C "$tmp/r" tag -a v0.1.0 -m v0.1.0
alert() { echo "{\"number\":$1,\"html_url\":\"https://example.invalid/$1\",\"rule\":{\"id\":\"go/x$1\",\"security_severity_level\":\"$2\"},\"most_recent_instance\":{\"location\":{\"path\":\"a.go\",\"start_line\":3}}}"; }
arr() { local IFS=,; echo "[$*]"; }
pre() { (cd "$tmp/r" && bash "$PRE" --ref HEAD --no-fetch "$@" 2>&1); }

echo '[]' >"$DEV_FILE"; echo '[]' >"$MAIN_FILE"
mig 000011 second
out="$(pre)"; rc=$?
assert_eq "clean: exit 0 ($out)" 0 "$rc"
assert_contains "clean: lists the added migration" "added: 000011" "$out"
assert_contains "clean: images not available is said" "not available" "$out"

arr "$(alert 1 high)" "$(alert 2 medium)" "$(alert 3 low)" >"$DEV_FILE"
out="$(pre)"; rc=$?
assert_eq "a high alert absent from main blocks" 1 "$rc"
assert_contains "the alert is listed" "go/x1" "$out"
assert_contains "the medium alert is a warning" "warning: 1 medium" "$out"
assert_not_contains "low alerts are not listed" "go/x3" "$out"

arr "$(alert 1 high)" >"$MAIN_FILE"; arr "$(alert 1 high)" >"$DEV_FILE"
out="$(pre)"; rc=$?
assert_eq "an alert main already has does not block" 0 "$rc"

echo '[]' >"$DEV_FILE"; echo '[]' >"$MAIN_FILE"
echo '{"component":"openctem-api","target":"alpine","pkg":"libssl3","installed":"3.0.1","fixed":"3.0.2","id":"CVE-1","severity":"HIGH","kind":"os"}' >"$tmp/img.ndjson"
out="$(pre --images "$tmp/img.ndjson")"; rc=$?
assert_eq "a fixable OS advisory blocks" 1 "$rc"
assert_contains "the advisory is listed" "CVE-1" "$out"
echo '{"component":"openctem-web","target":"node","pkg":"x","installed":"1","fixed":"2","id":"CVE-2","severity":"HIGH","kind":"library"}' >"$tmp/img.ndjson"
out="$(pre --images "$tmp/img.ndjson")"; rc=$?
assert_eq "a fixable application advisory only warns" 0 "$rc"

mig 000009 late
out="$(pre)"; rc=$?
assert_eq "a migration below the last release's highest blocks" 1 "$rc"

# Release lines: versions.yaml latest behind the published release blocks.
printf 'sensor:\n  product: openctemio-sensor\n  latest: v0.2.0\n  image: ghcr.io/openctemio/sensor\nsdk:\n  latest: v0.5.0\n' >"$tmp/r/versions.yaml"
git -C "$tmp/r" rm -q --cached -r api/migrations/000009_late.up.sql api/migrations/000009_late.down.sql >/dev/null 2>&1
rm -f "$tmp/r/api/migrations/000009_late."*
git -C "$tmp/r" add -A; git -C "$tmp/r" commit -q -m manifest
out="$(pre)"; rc=$?
assert_eq "release lines current: exit 0 ($out)" 0 "$rc"
assert_contains "the sensor line is reported" "sensor: v0.2.0 (current)" "$out"
out="$(SENSOR_PUBLISHED=v0.3.0 pre)"; rc=$?
assert_eq "a product behind its published release blocks" 1 "$rc"
assert_contains "the stale line is named" "sensor.latest is v0.2.0, openctemio/sensor published v0.3.0" "$out"

echo 'not json' >"$DEV_FILE"
out="$(pre)"; rc=$?
assert_eq "unreadable alerts are a blocker, not a pass" 1 "$rc"

finish
