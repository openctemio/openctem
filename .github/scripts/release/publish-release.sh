#!/usr/bin/env bash
# publish-release.sh <tag> <notes-file> <asset>...
#
# Creates the GitHub release for <tag> with <notes-file> followed by the notes
# GitHub generates from the merged pull requests, and uploads <asset>s. Safe to
# rerun: an existing release keeps its notes and only gets the assets
# (--clobber). Every call goes through gh-retry.sh (GitHub 5xx incidents).
set -euo pipefail
tag="$1" notes="$2"
shift 2
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
retry="${here}/gh-retry.sh"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

if gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
  echo "release ${tag} exists; uploading assets only"
else
  # A create that failed with a 5xx may still have created the release; the
  # retry then fails with "already exists", which the view below settles.
  # GitHub refuses a release body over 125,000 characters, which the notes it
  # generates from a long train's pull requests can exceed. Build the body
  # here and cut the generated part at a line, linking the full comparison.
  # The changelog in <notes-file> alone can pass the limit (a long train): it
  # is then cut before the first "### " entry that does not fit, and the
  # generated list is left out.
  body="$(mktemp)"
  max=120000
  prev="$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)"
  generated="$(bash "$retry" api "repos/${repo}/releases/generate-notes" -f tag_name="$tag" --jq .body || true)"
  size="$(wc -c <"$notes")"
  {
    if [ "$size" -gt "$max" ]; then
      awk -v max="$max" '
        function flush() {
          if (!cut && size + length(sec) <= max) { printf "%s", sec; size += length(sec); kept += has }
          else if (has) cut = 1
          sec = ""; has = 0
        }
        /^### / { flush(); n++; has = 1 }
        { sec = sec $0 "\n" }
        END { flush(); printf "\n_The list is cut here (%d of %d entries): GitHub limits a release to 125,000 characters._\n", kept, n }
      ' "$notes"
      echo "Full list: https://github.com/${repo}/tree/${tag}/server/changelog.d"
      [ -n "$prev" ] && echo "Full comparison: https://github.com/${repo}/compare/${prev}...${tag}"
    else
      limit=$((max - size))
      cat "$notes"
      echo
      if [ "${#generated}" -le "$limit" ]; then
        printf '%s\n' "$generated"
      else
        printf '%s\n' "${generated:0:$limit}" | sed '$d'
        echo
        echo "_The list is cut here: GitHub limits a release to 125,000 characters._"
        [ -n "$prev" ] && echo "Full list: https://github.com/${repo}/compare/${prev}...${tag}"
      fi
    fi
  } >"$body"
  # Only the newest release line is GitHub's "Latest" release (install
  # scripts and the release feed read it); a hotfix of an older line is not.
  newest="$(git ls-remote --tags --refs "https://github.com/${repo}.git" 'v*' |
    sed 's#.*refs/tags/##' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)"
  [ -n "$newest" ] || { echo "could not list the release tags" >&2; exit 1; }
  latest=false
  [ "$newest" = "$tag" ] && latest=true
  if ! GH_RETRY_ATTEMPTS="${GH_RETRY_ATTEMPTS:-6}" bash "$retry" release create "$tag" -R "$repo" \
      --verify-tag --title "$tag" --notes-file "$body" --latest="$latest"; then
    gh release view "$tag" -R "$repo" >/dev/null 2>&1 || { echo "could not create release ${tag}" >&2; exit 1; }
  fi
fi
if [ "$#" -gt 0 ]; then
  bash "$retry" release upload "$tag" -R "$repo" --clobber "$@"
fi
