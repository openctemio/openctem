#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# sync-versions.sh: copy versions.yaml into every default that repeats it
# (api/docs/rfcs/RFC-037).
#
#   sync-versions.sh            rewrite the consumers in place
#   sync-versions.sh --check    change nothing; list each drifted default and
#                               exit 1 (the "Version consistency" CI job)
#   sync-versions.sh --root DIR operate on another checkout (tests)
#
# THE CONSUMER TABLE BELOW IS THE ONLY PLACE a versioned default is allowed to
# live outside versions.yaml. Adding a default somewhere else? Add a row.
#
# It also checks the invariants that have no value to copy:
#   - versions.yaml values are versions (vX.Y.Z) or "" where "" is allowed;
#   - platform.release is not newer than the newest tag (when tags are present);
#   - web/package.json carries the placeholder version 0.0.0, never a release.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

ROOT="$(cd "$HERE/../../.." && pwd)"
CHECK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1 ;;
    --root) ROOT="$(cd "$2" && pwd)"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); if ($0 !~ /^shellcheck/) print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

MANIFEST="$ROOT/versions.yaml"
[[ -f "$MANIFEST" ]] || { echo "no versions.yaml at $ROOT" >&2; exit 2; }

# key | file (relative to the root) | closer | sed -E regex. Group 1 is the
# text before the value, group 2 the value; the regex ends right after the
# value's closing delimiter (closer: '"', '}' or nothing), which is put back.
CONSUMERS=(
  'platform.release|api/deploy/.env.example||^(OPENCTEM_VERSION=)([^#]*)$'
  'platform.release|api/deploy/docker-compose.yml||(OPENCTEM_VERSION is required, e\.g\. )([^}]*)'
  'sensor.latest|api/internal/config/config.go|"|^(const DefaultSensorLatestVersion = ")([^"]*)"'
  'sensor.latest|api/internal/infra/http/handler/sensor_handler.go|"|^(const DefaultSensorImage = "ghcr\.io/openctemio/sensor:)([^"]*)"'
  'sensor.latest|api/deploy/docker-compose.yml|}|(SENSOR_LATEST_VERSION: \$\{SENSOR_LATEST_VERSION:-)([^}]*)\}'
  'sensor.latest|api/.env.example||^(# SENSOR_LATEST_VERSION=)(.*)$'
  'sensor.min|api/internal/config/config.go|"|^(const DefaultSensorMinVersion = ")([^"]*)"'
  'sensor.min|api/deploy/docker-compose.yml|}|(SENSOR_MIN_VERSION: \$\{SENSOR_MIN_VERSION:-)([^}]*)\}'
  'sdk.latest|api/internal/config/config.go|"|^(const DefaultSensorSDKLatestVersion = ")([^"]*)"'
  'sdk.latest|api/deploy/docker-compose.yml|}|(SENSOR_SDK_LATEST_VERSION: \$\{SENSOR_SDK_LATEST_VERSION:-)([^}]*)\}'
  'sdk.latest|api/.env.example||^(# SENSOR_SDK_LATEST_VERSION=)(.*)$'
  'sdk.min|api/internal/config/config.go|"|^(const DefaultSensorSDKMinVersion = ")([^"]*)"'
  'sdk.min|api/deploy/docker-compose.yml|}|(SENSOR_SDK_MIN_VERSION: \$\{SENSOR_SDK_MIN_VERSION:-)([^}]*)\}'
)

# Keys that may be "" (= not set). The others must be a version.
OPTIONAL_KEYS=" sensor.min sdk.min "

problems=0
problem() { echo "::error::$*"; problems=$((problems + 1)); }

declare -A VALUE
for key in platform.release sensor.latest sensor.min sdk.latest sdk.min chart.version; do
  if ! v="$(rel_yaml_get "$MANIFEST" "$key")"; then
    problem "versions.yaml: $key is missing"
    continue
  fi
  VALUE[$key]="$v"
  if [[ "$key" == chart.version ]]; then
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || problem "versions.yaml: chart.version '$v' is not X.Y.Z"
  elif [[ -z "$v" ]]; then
    [[ "$OPTIONAL_KEYS" == *" $key "* ]] || problem "versions.yaml: $key must be set"
  elif ! rel_is_version "$v"; then
    problem "versions.yaml: $key '$v' is not vX.Y.Z"
  fi
done

latest_tag="$(rel_latest_tag "$ROOT" 2>/dev/null || true)"
if [[ -n "$latest_tag" && -n "${VALUE[platform.release]:-}" ]] &&
  rel_version_gt "${VALUE[platform.release]}" "$latest_tag"; then
  problem "versions.yaml: platform.release ${VALUE[platform.release]} is newer than the newest tag $latest_tag (it names a released tag, bumped by the release workflow after tagging)"
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

if [[ $problems -gt 0 ]]; then
  echo
  echo "$problems problem(s). Fix versions.yaml, then run .github/scripts/release/sync-versions.sh"
  exit 1
fi
[[ $CHECK -eq 1 ]] && echo "versions.yaml and its ${#CONSUMERS[@]} consumers agree"
exit 0
