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
  body="$(mktemp)"
  generated="$(bash "$retry" api "repos/${repo}/releases/generate-notes" -f tag_name="$tag" --jq .body || true)"
  limit=$((120000 - $(wc -c <"$notes")))
  {
    cat "$notes"
    echo
    if [ "${#generated}" -le "$limit" ]; then
      printf '%s\n' "$generated"
    else
      printf '%s\n' "${generated:0:$limit}" | sed '$d'
      echo
      echo "_The list is cut here: GitHub limits a release to 125,000 characters._"
      prev="$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)"
      [ -n "$prev" ] && echo "Full list: https://github.com/${repo}/compare/${prev}...${tag}"
    fi
  } >"$body"
  if ! GH_RETRY_ATTEMPTS="${GH_RETRY_ATTEMPTS:-6}" bash "$retry" release create "$tag" -R "$repo" \
      --verify-tag --title "$tag" --notes-file "$body"; then
    gh release view "$tag" -R "$repo" >/dev/null 2>&1 || { echo "could not create release ${tag}" >&2; exit 1; }
  fi
fi
if [ "$#" -gt 0 ]; then
  bash "$retry" release upload "$tag" -R "$repo" --clobber "$@"
fi
