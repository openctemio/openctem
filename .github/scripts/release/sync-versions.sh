#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# sync-versions.sh: copy versions.yaml into every default that repeats it
# (api/docs/rfcs/RFC-037).
#
# The API reads every version default from a byte-for-byte copy of
# versions.yaml embedded at build time (api/internal/versions/versions.yaml):
# go:embed cannot reach outside the Go module in api/. This script writes that
# copy; no Go file holds a version, so a bump changes YAML (and the few
# non-Go consumers below) only. A sensor or SDK release needs no bump at all:
# running instances learn it from the signed release feed (RFC-037 §12).
#
#   sync-versions.sh            rewrite the consumers in place
#   sync-versions.sh --check    change nothing; list each drifted default and
#                               exit 1 (the "Version consistency" CI job)
#   sync-versions.sh --root DIR operate on another checkout (tests)
#   sync-versions.sh --release vX.Y.Z
#                               the checkout is the release branch of vX.Y.Z
#                               (or main right after it merged): platform.release
#                               must be exactly vX.Y.Z, which may be newer than
#                               the newest tag because the tag comes after
#
# THE CONSUMER TABLE BELOW IS THE ONLY PLACE a versioned default is allowed to
# live outside versions.yaml. Adding a default somewhere else? Add a row (a
# Go default reads internal/versions instead).
#
# It also checks the invariants that have no value to copy:
#   - versions.yaml values are versions (vX.Y.Z) or "" where "" is allowed,
#     and every sensor product section (any section other than platform,
#     sdk, ci and chart) has its keys (the API's tests check the rest);
#   - platform.release is not newer than the newest tag (when tags are present),
#     except on the release branch that is about to create that tag (--release);
#   - web/package.json carries the placeholder version 0.0.0, never a release.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

ROOT="$(cd "$HERE/../../.." && pwd)"
CHECK=0
RELEASE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1 ;;
    --root) ROOT="$(cd "$2" && pwd)"; shift ;;
    --release) RELEASE="$2"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); if ($0 !~ /^shellcheck/) print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[[ -z "$RELEASE" ]] || rel_is_version "$RELEASE" || { echo "--release must be vX.Y.Z, got '$RELEASE'" >&2; exit 2; }
MANIFEST="$ROOT/versions.yaml"
[[ -f "$MANIFEST" ]] || { echo "no versions.yaml at $ROOT" >&2; exit 2; }

# The API's embedded copy of versions.yaml (whole file, byte for byte).
EMBEDDED="api/internal/versions/versions.yaml"

# key | file (relative to the root) | closer | sed -E regex. Group 1 is the
# text before the value, group 2 the value; the regex ends right after the
# value's closing delimiter (closer: '"', '}' or nothing), which is put back.
# Never a Go file: Go reads the embedded copy.
CONSUMERS=(
  'platform.release|api/deploy/.env.example||^(OPENCTEM_VERSION=)([^#]*)$'
  'platform.release|api/deploy/docker-compose.yml|}|(OPENCTEM_VERSION:-)([^}]*)\}'
  'platform.release|api/deploy/docker-compose.job-signer.yml|}|(OPENCTEM_VERSION:-)([^}]*)\}'
  'platform.release|api/deploy/docker-compose.sensor.yml|}|(OPENCTEM_VERSION:-)([^}]*)\}'
  'sensor.latest|api/deploy/docker-compose.sensor.yml|}|(SENSOR_VERSION:-)([^}]*)\}'
  'ci.latest|web/src/features/ci-runners/lib/ci.ts|'"'"'|^(export const CI_RELEASE = '"'"')([^'"'"']*)'"'"''
)

# The sections that are not sensor products.
FIXED_SECTIONS=" platform sdk ci chart "

problems=0
problem() { echo "::error::$*"; problems=$((problems + 1)); }

# Every top-level section that is not a fixed one is a sensor product.
mapfile -t PRODUCTS < <(awk '/^[^[:space:]#][^:]*:[[:space:]]*(#.*)?$/ { s = $0; sub(/:.*/, "", s); print s }' "$MANIFEST" |
  while read -r s; do [[ "$FIXED_SECTIONS" == *" $s "* ]] || echo "$s"; done)
[[ " ${PRODUCTS[*]} " == *" sensor "* ]] || problem "versions.yaml: the scanning sensor section (sensor:) is missing"

# key | kind: version, version? (may be ""), versions (space-separated, may be
# ""), chart (X.Y.Z), text (set), text? (may be "").
CHECKS=(platform.release:version sdk.latest:version sdk.min:version? sdk.advisories:versions ci.latest:version ci.min:version? chart.version:chart)
for prod in "${PRODUCTS[@]}"; do
  CHECKS+=("$prod.product:text" "$prod.latest:version" "$prod.min:version?" "$prod.image:text" "$prod.install:text" "$prod.release_identity:text")
done

declare -A VALUE
for check in "${CHECKS[@]}"; do
  key="${check%:*}" kind="${check##*:}"
  if ! v="$(rel_yaml_get "$MANIFEST" "$key")"; then
    problem "versions.yaml: $key is missing"
    continue
  fi
  VALUE[$key]="$v"
  case "$kind" in
    chart) [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || problem "versions.yaml: $key '$v' is not X.Y.Z" ;;
    text) [[ -n "$v" ]] || problem "versions.yaml: $key must be set" ;;
    versions)
      for a in $v; do rel_is_version "$a" || problem "versions.yaml: $key '$a' is not vX.Y.Z"; done ;;
    version | version?)
      if [[ -z "$v" ]]; then
        [[ "$kind" == "version?" ]] || problem "versions.yaml: $key must be set"
      elif ! rel_is_version "$v"; then
        problem "versions.yaml: $key '$v' is not vX.Y.Z"
      fi ;;
  esac
done

# platform.release names the newest release. Only a release branch (--release)
# may name the version it is about to tag, and it must name exactly that.
latest_tag="$(rel_latest_tag "$ROOT" 2>/dev/null || true)"
if [[ -n "$RELEASE" ]]; then
  [[ "${VALUE[platform.release]:-}" == "$RELEASE" ]] ||
    problem "versions.yaml: platform.release is '${VALUE[platform.release]:-}', but this is the release branch of $RELEASE: its checkout must default to $RELEASE (cut-release.sh writes it)"
elif [[ -n "$latest_tag" && -n "${VALUE[platform.release]:-}" ]] &&
  rel_version_gt "${VALUE[platform.release]}" "$latest_tag"; then
  problem "versions.yaml: platform.release ${VALUE[platform.release]} is newer than the newest tag $latest_tag (only release/${VALUE[platform.release]} may say that, checked with --release)"
fi

pkg="$ROOT/web/package.json"
if [[ -f "$pkg" ]]; then
  pkg_version="$(sed -nE 's/^  "version": "([^"]*)",?$/\1/p' "$pkg" | head -n 1)"
  if [[ "$pkg_version" != "0.0.0" ]]; then
    problem "web/package.json: version is '$pkg_version'; it must stay 0.0.0. The web version comes from the release tag (NEXT_PUBLIC_APP_VERSION) or git, never from package.json"
  fi
fi

for row in "${CONSUMERS[@]}"; do
  IFS='|' read -r key rel closer regex <<<"$row"
  file="$ROOT/$rel"
  [[ -n "${VALUE[$key]+x}" ]] || continue
  if [[ ! -f "$file" ]]; then
    problem "$rel: missing (consumer of $key)"
    continue
  fi
  if ! grep -qE "$regex" "$file"; then
    problem "$rel: no default for $key matches /$regex/ (the line moved or changed shape: update the row in sync-versions.sh)"
    continue
  fi
  want="${VALUE[$key]}"
  # The value goes between group 1 and the closer; "|" is the sed delimiter
  # (no regex or value here contains one).
  tmp="$(mktemp)"
  sed -E "s|${regex}|\\1${want}${closer}|" "$file" >"$tmp"
  if ! cmp -s "$file" "$tmp"; then
    if [[ $CHECK -eq 1 ]]; then
      have="$(grep -E "$regex" "$file" | head -n 1 | sed -E "s|.*${regex}.*|\\2|")"
      problem "$rel: $key default is '${have}', versions.yaml says '${want}'"
    else
      cat "$tmp" >"$file"
      echo "updated $rel ($key = ${want:-\"\"})"
    fi
  fi
  rm -f "$tmp"
done

# The API's embedded copy is the manifest, byte for byte.
embedded="$ROOT/$EMBEDDED"
if ! cmp -s "$MANIFEST" "$embedded"; then
  if [[ $CHECK -eq 1 ]]; then
    problem "$EMBEDDED: differs from versions.yaml (the API embeds this copy)"
  else
    mkdir -p "$(dirname "$embedded")"
    cat "$MANIFEST" >"$embedded"
    echo "updated $EMBEDDED"
  fi
fi

if [[ $problems -gt 0 ]]; then
  echo
  echo "$problems problem(s). Fix versions.yaml, then run .github/scripts/release/sync-versions.sh"
  exit 1
fi
[[ $CHECK -eq 1 ]] && echo "versions.yaml, its embedded copy and its ${#CONSUMERS[@]} consumers agree"
exit 0
