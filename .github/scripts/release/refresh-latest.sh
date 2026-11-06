#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# refresh-latest.sh [--root DIR]: move each first-party component's built-in
# "latest" in versions.yaml forward to its newest published release
# (server/docs/rfcs/RFC-037 §12, server/docs/architecture/version-check.md).
#
# cut-release.sh runs it on the release branch, so the release's built-in
# versions (the fallback of an instance that cannot reach the release feed)
# are as new as the release itself. Nobody bumps a "latest" by hand or by a
# pull request per component release any more.
#
# Components: every sensor product section of versions.yaml (repository from
# its release_identity, image from its image), the SDK (openctemio/sdk-go, no
# image) and the CI runner (openctemio/ci, image ghcr.io/openctemio/ci). Each
# is resolved by feed-components.sh, the same rule the release feed uses: the
# newest stable vX.Y.Z release whose image is published.
#
# A "latest" only moves forward. "min" is never touched: it is this
# platform's compatibility floor and changes only with a protocol change.
# A component that cannot be resolved (no release, registry or API down)
# keeps its value with a warning: a stale fallback never stops a release.
# The caller runs sync-versions.sh afterwards to copy the values to their
# consumers.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

ROOT="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); if ($0 !~ /^shellcheck/) print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
MANIFEST="$ROOT/versions.yaml"
[[ -f "$MANIFEST" ]] || { echo "refresh-latest: no versions.yaml at $ROOT" >&2; exit 2; }

identity_re='^https://github\.com/(openctemio/[A-Za-z0-9._-]+)/\.github/workflows/'

# components: "<section> <repository> <image or ->" per line.
components() {
  local section identity image
  while IFS= read -r section; do
    case "$section" in
      sdk) echo "sdk openctemio/sdk-go -" ;;
      ci) echo "ci openctemio/ci ghcr.io/openctemio/ci" ;;
      *)
        identity="$(rel_yaml_get "$MANIFEST" "$section.release_identity" 2>/dev/null || true)"
        image="$(rel_yaml_get "$MANIFEST" "$section.image" 2>/dev/null || true)"
        if [[ "$identity" =~ $identity_re && "$image" == ghcr.io/openctemio/* ]]; then
          echo "$section ${BASH_REMATCH[1]} $image"
        fi ;;
    esac
  done < <(grep -E '^[a-z0-9][a-z0-9-]*:[[:space:]]*(#.*)?$' "$MANIFEST" | sed 's/:.*//')
}

while read -r section repo image; do
  have="$(rel_yaml_get "$MANIFEST" "$section.latest" 2>/dev/null || true)"
  rel_is_version "$have" || continue
  if ! json="$(printf '%s %s %s\n' "$section" "$repo" "$image" | bash "$HERE/feed-components.sh" 2>/dev/null)"; then
    echo "::warning::refresh-latest: no published release of $repo could be read; $section.latest stays $have" >&2
    continue
  fi
  want="$(jq -r '.[0].version // empty' <<<"$json")"
  if ! rel_is_version "$want"; then
    echo "::warning::refresh-latest: $repo answered no vX.Y.Z release; $section.latest stays $have" >&2
  elif rel_version_gt "$want" "$have"; then
    rel_yaml_set "$MANIFEST" "$section.latest" "$want"
    echo "refresh-latest: $section.latest $have -> $want" >&2
  else
    echo "refresh-latest: $section.latest $have (current)" >&2
  fi
done < <(components)
