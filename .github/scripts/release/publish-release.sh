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
  if ! GH_RETRY_ATTEMPTS="${GH_RETRY_ATTEMPTS:-6}" bash "$retry" release create "$tag" -R "$repo" \
      --verify-tag --title "$tag" --notes-file "$notes" --generate-notes; then
    gh release view "$tag" -R "$repo" >/dev/null 2>&1 || { echo "could not create release ${tag}" >&2; exit 1; }
  fi
fi
if [ "$#" -gt 0 ]; then
  bash "$retry" release upload "$tag" -R "$repo" --clobber "$@"
fi
