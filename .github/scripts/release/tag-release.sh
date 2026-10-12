#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# tag-release.sh: tag a merged release (api/docs/rfcs/RFC-037 §4.2).
#
#   tag-release.sh --version vX.Y.Z --commit SHA --release-head SHA [--push]
#                  [--remote origin] [--main main] [--repo DIR]
#
#   --commit        the merge commit on main (the PR's merge_commit_sha)
#   --release-head  the release branch's head that was merged
#
# Refuses unless: the version is vX.Y.Z and greater than every existing
# release tag, the tag does not exist (locally or on the remote), the commit
# is on main, and the commit's tree is exactly the release branch's tree (what
# CI tested is what gets the tag). Then creates an annotated tag and, with
# --push, pushes only that tag.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

VERSION=""
COMMIT=""
HEAD_SHA=""
PUSH=0
REMOTE="origin"
MAIN="main"
REPO="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift ;;
    --commit) COMMIT="$2"; shift ;;
    --release-head) HEAD_SHA="$2"; shift ;;
    --push) PUSH=1 ;;
    --remote) REMOTE="$2"; shift ;;
    --main) MAIN="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "REFUSING: $*" >&2; exit 1; }
g() { git -C "$REPO" "$@"; }

rel_is_version "$VERSION" || { echo "--version must be vX.Y.Z, got '$VERSION'" >&2; exit 2; }
[[ -n "$COMMIT" && -n "$HEAD_SHA" ]] || { echo "--commit and --release-head are required" >&2; exit 2; }

g fetch --quiet --tags "$REMOTE" "+refs/heads/$MAIN:refs/remotes/$REMOTE/$MAIN"
g cat-file -e "$HEAD_SHA^{commit}" 2>/dev/null || g fetch --quiet "$REMOTE" "$HEAD_SHA" || die "cannot fetch $HEAD_SHA"
COMMIT="$(g rev-parse --verify "$COMMIT^{commit}")"

g rev-parse -q --verify "refs/tags/$VERSION" >/dev/null && die "tag $VERSION already exists"
g ls-remote --exit-code --tags "$REMOTE" "refs/tags/$VERSION" >/dev/null 2>&1 && die "tag $VERSION already exists on $REMOTE"
last="$(rel_latest_tag "$REPO")"
if [[ -n "$last" ]] && ! rel_version_gt "$VERSION" "$last"; then
  die "$VERSION is not greater than the last release $last"
fi
g merge-base --is-ancestor "$COMMIT" "refs/remotes/$REMOTE/$MAIN" || die "$COMMIT is not on $MAIN"
[[ "$(g rev-parse "$COMMIT^{tree}")" == "$(g rev-parse "$HEAD_SHA^{tree}")" ]] ||
  die "$MAIN's tree at $COMMIT differs from the release branch ($HEAD_SHA); not tagging what CI did not test"

g -c user.name="${GIT_AUTHOR_NAME:-openctem-release}" -c user.email="${GIT_AUTHOR_EMAIL:-release@openctem.invalid}" \
  tag -a "$VERSION" "$COMMIT" -m "OpenCTEM $VERSION"
echo "tagged $VERSION at $COMMIT" >&2
if [[ $PUSH -eq 1 ]]; then
  g push --quiet "$REMOTE" "refs/tags/$VERSION"
  echo "pushed $VERSION" >&2
fi
echo "TAG=$VERSION"
echo "COMMIT=$COMMIT"
