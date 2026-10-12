#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# helm-bump.sh: point the openctem chart at a new platform release
# (api/docs/rfcs/RFC-037 §4.2).
#
#   helm-bump.sh --chart PATH/Chart.yaml --app-version vX.Y.Z
#
# Sets appVersion to vX.Y.Z and bumps the chart's own version: minor when the
# platform's major or minor changed, patch otherwise (a chart that deploys a
# new feature release is a feature release of the chart). Exit 4 with no
# change when appVersion already is vX.Y.Z.
# Prints KEY=VALUE lines: CHART_VERSION, PREVIOUS_CHART_VERSION, PREVIOUS_APP_VERSION.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

CHART=""
APP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --chart) CHART="$2"; shift ;;
    --app-version) APP="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -f "$CHART" ]] || { echo "--chart must name a Chart.yaml" >&2; exit 2; }
rel_is_version "$APP" || { echo "--app-version must be vX.Y.Z" >&2; exit 2; }

cur_chart="$(sed -nE 's/^version:[[:space:]]*"?([0-9]+\.[0-9]+\.[0-9]+)"?[[:space:]]*$/\1/p' "$CHART")"
cur_app="$(sed -nE 's/^appVersion:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p' "$CHART")"
[[ -n "$cur_chart" ]] || { echo "no 'version: X.Y.Z' line in $CHART" >&2; exit 2; }
[[ -n "$cur_app" ]] || { echo "no 'appVersion:' line in $CHART" >&2; exit 2; }
if [[ "$cur_app" == "$APP" ]]; then
  echo "appVersion already $APP" >&2
  exit 4
fi

IFS=. read -r cmaj cmin cpat <<<"$cur_chart"
old="${cur_app#v}"; new="${APP#v}"
if [[ "${old%.*}" != "${new%.*}" ]]; then
  next_chart="${cmaj}.$((cmin + 1)).0"
else
  next_chart="${cmaj}.${cmin}.$((cpat + 1))"
fi

sed -i -E "s/^version:[[:space:]]*\"?[0-9]+\.[0-9]+\.[0-9]+\"?[[:space:]]*$/version: ${next_chart}/" "$CHART"
sed -i -E "s/^appVersion:.*$/appVersion: \"${APP}\"/" "$CHART"
echo "CHART_VERSION=$next_chart"
echo "PREVIOUS_CHART_VERSION=$cur_chart"
echo "PREVIOUS_APP_VERSION=$cur_app"
