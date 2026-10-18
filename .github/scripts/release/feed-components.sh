#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# feed-components.sh [LIST]: the newest stable release of each first-party
# component, as the JSON array `release-feed build -components` signs into the
# release feed (api/docs/rfcs/RFC-037-versioning-and-release-train.md §12).
#
# LIST (default: stdin) is what `go run ./cmd/release-feed components` prints:
# one "<component> <repository> <image repository or ->" per line.
#
# For each component: the newest vX.Y.Z release of its repository that is
# neither a draft nor a pre-release. For a component with an image, the
# release counts only once its image tag is published (the tag starts the
# release and the image builds in parallel), and its manifest digest is
# recorded; the newest FEED_CANDIDATES (default 3) releases are tried. A
# component that cannot be resolved fails the run: a feed that silently
# left one out would send every instance back to its built-in version.
#
# Needs gh (any token that can read public repositories), jq, and docker with
# buildx (an anonymous pull of a public image).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANDIDATES="${FEED_CANDIDATES:-3}"
LIST="${1:-/dev/stdin}"

component_re='^[a-z0-9][a-z0-9-]{0,63}$'
repo_re='^openctemio/[A-Za-z0-9._-]+$'
digest_re='^sha256:[0-9a-f]{64}$'

out='[]'
while read -r comp repo image extra; do
  [[ -z "${comp:-}" || "$comp" == \#* ]] && continue
  if [[ -n "${extra:-}" || ! "$comp" =~ $component_re || ! "${repo:-}" =~ $repo_re || -z "${image:-}" ]]; then
    echo "::error::feed-components: malformed line: $comp ${repo:-} ${image:-} ${extra:-}" >&2
    exit 1
  fi
  rows="$(bash "$HERE/gh-retry.sh" release list -R "$repo" --exclude-drafts --exclude-pre-releases \
    --json tagName,publishedAt --limit 50)"
  mapfile -t tags < <(jq -r '.[] | .tagName | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' <<<"$rows" | sort -rV)
  chosen="" digest=""
  for tag in "${tags[@]:0:$CANDIDATES}"; do
    if [[ "$image" == "-" ]]; then
      chosen="$tag"
      break
    fi
    d="$(docker buildx imagetools inspect "$image:$tag" --format '{{json .Manifest}}' 2>/dev/null | jq -r '.digest // empty' || true)"
    if [[ "$d" =~ $digest_re ]]; then
      chosen="$tag" digest="$d"
      break
    fi
    echo "feed-components: $image:$tag is not published (yet); trying the release before it" >&2
  done
  if [[ -z "$chosen" ]]; then
    echo "::error::feed-components: no usable release of $repo (component $comp)" >&2
    exit 1
  fi
  published="$(jq -r --arg t "$chosen" '[.[] | select(.tagName == $t)][0].publishedAt' <<<"$rows")"
  out="$(jq --arg c "$comp" --arg v "$chosen" --arg p "$published" --arg d "$digest" \
    --arg n "https://github.com/$repo/releases/tag/$chosen" \
    '. + [{component: $c, version: $v, published_at: $p, notes_url: $n} + (if $d == "" then {} else {digest: $d} end)]' <<<"$out")"
  echo "feed-components: $comp $chosen ${digest:-}" >&2
done <"$LIST"

if [[ "$out" == "[]" ]]; then
  echo "::error::feed-components: no component listed" >&2
  exit 1
fi
printf '%s\n' "$out"
