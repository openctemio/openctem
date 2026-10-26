#!/usr/bin/env bash
# Self-test of tool-pins.py with a fixture instead of the GitHub API.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/tool-pins.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

check() { # name expected-rc actual-rc
  if [ "$2" != "$3" ]; then echo "FAIL: $1 (exit $3, want $2)"; fails=$((fails + 1)); else echo "ok: $1"; fi
}
tab=$'\t'

cat >"$tmp/Makefile" <<'EOF'
LINT_VERSION ?= v1.64.8
EOF
cat >"$tmp/ci.yml" <<'EOF'
env:
  CHECK_VERSION: 2025.1.1
  TOOL_VERSION: 1.7.7
EOF
printf '%s\n' \
  "# comment" \
  "lint${tab}acme/lint${tab}releases${tab}1${tab}Makefile${tab}^LINT_VERSION \\?= (v[0-9.]+)${tab}" \
  "check${tab}acme/check${tab}tags${tab}-${tab}ci.yml${tab}CHECK_VERSION: ([0-9.]+)${tab}checksum" \
  "tool${tab}acme/tool${tab}releases${tab}-${tab}ci.yml${tab}TOOL_VERSION: ([0-9.]+)${tab}" \
  "later${tab}acme/later${tab}releases${tab}-${tab}later.yml${tab}X: ([0-9.]+)${tab}optional" \
  >"$tmp/pins.tsv"

run() { TOOL_PINS_FIXTURE="$tmp/fixture.json" python3 "$script" --manifest "$tmp/pins.tsv" --root "$tmp" "$@"; }

# Everything current: the major cap hides v2, the calendar pin ignores v0.x tags,
# a release candidate is not a release.
cat >"$tmp/fixture.json" <<'EOF'
{"acme/lint": ["v2.0.0", "v1.64.8", "v1.64.7"],
 "acme/check": ["v0.9.0", "2025.1.1", "2025.2rc1"],
 "acme/tool": ["v1.7.7", "v1.8.0-rc.1"]}
EOF
set +e
out="$(run 2>&1)"; rc=$?
set -e
check "all current exits 0" 0 "$rc"
case "$out" in *"3 pin(s) current, 0 to bump, 1 not present yet"*) echo "ok: summary";; *) echo "FAIL: summary: $out"; fails=$((fails + 1));; esac

# Newer releases are reported, with the checksum note and the major-cap note.
cat >"$tmp/fixture.json" <<'EOF'
{"acme/lint": ["v2.0.0", "v1.65.0"],
 "acme/check": ["v0.9.0", "2025.2.0"],
 "acme/tool": ["v1.7.8"]}
EOF
set +e
out="$(run --report "$tmp/report.md" 2>&1)"; rc=$?
set -e
check "outdated exits 10" 10 "$rc"
for want in '`v1.65.0`' '`2025.2.0`' '`v1.7.8`' 'update the SHA-256 next to the pin' 'stays on major 1 on purpose'; do
  case "$out" in *"$want"*) echo "ok: report has $want";; *) echo "FAIL: report lacks $want"; fails=$((fails + 1));; esac
done
case "$out" in *'`v2.0.0`'*) echo "FAIL: the major cap was ignored"; fails=$((fails + 1));; *) echo "ok: major cap";; esac
[ -s "$tmp/report.md" ] && echo "ok: report file written" || { echo "FAIL: report file"; fails=$((fails + 1)); }

# A pin that cannot be found is an error, never a pass.
sed -i 's/TOOL_VERSION/RENAMED_VERSION/' "$tmp/ci.yml"
set +e
out="$(run 2>&1)"; rc=$?
set -e
check "a missing pin exits 1" 1 "$rc"
case "$out" in *"no pin matches"*) echo "ok: missing pin message";; *) echo "FAIL: message: $out"; fails=$((fails + 1));; esac

# The real manifest parses and every non-optional pin is found.
printf '{}' >"$tmp/real.json"
set +e
out="$(TOOL_PINS_FIXTURE="$tmp/real.json" python3 "$script" 2>&1)"; rc=$?
set -e
case "$out" in *"no stable upstream version found"*) echo "ok: the real manifest resolved every pin";; *) echo "FAIL: real manifest: $out"; fails=$((fails + 1));; esac

[ "$fails" -eq 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "tool-pins self-test passed"
