#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# post-release.sh: the follow-up branch for develop after vX.Y.Z is tagged
# (api/docs/rfcs/RFC-037 §4.2).
#
#   post-release.sh --version vX.Y.Z [--mode train|hotfix]
#                   [--push] [--remote origin] [--develop develop] [--main main]
#                   [--repo DIR]
#
# A train: builds chore/post-release-vX.Y.Z from develop with main (the tag)
# merged in using `-s ours`. The merge makes the tag an ancestor of develop, so
# `git pull` fetches it, dev builds see it (RFC-037 §3.3) and the next cut needs
# no -s ours; and it changes no file: develop's tree stays byte for byte, so no
# version ever lands on develop (the install version, api/deploy/VERSION, lives
# on the release branch and main only). Refused when main has a file develop
# lacks (a fix made on main alone would be silently dropped).
#
# A hotfix: nothing to do. Its commits are already on develop as the originals
# and it changes no version file; the script says so and exits 0 without a branch.
#
# Prints KEY=VALUE lines: BRANCH, HEAD (none for a hotfix).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

VERSION=""
MODE="train"
PUSH=0
REMOTE="origin"
DEVELOP="develop"
MAIN="main"
REPO="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift ;;
    --mode) MODE="$2"; shift ;;
    --push) PUSH=1 ;;
    --remote) REMOTE="$2"; shift ;;
    --develop) DEVELOP="$2"; shift ;;
    --main) MAIN="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "REFUSING: $*" >&2; exit 1; }
g() { git -C "$REPO" "$@"; }

rel_is_version "$VERSION" || { echo "--version must be vX.Y.Z, got '$VERSION'" >&2; exit 2; }
[[ "$MODE" == train || "$MODE" == hotfix ]] || { echo "--mode must be train or hotfix" >&2; exit 2; }
BRANCH="chore/post-release-$VERSION"

g fetch --quiet --tags "$REMOTE" "+refs/heads/$DEVELOP:refs/remotes/$REMOTE/$DEVELOP" "+refs/heads/$MAIN:refs/remotes/$REMOTE/$MAIN"
dev_ref="refs/remotes/$REMOTE/$DEVELOP"
g rev-parse -q --verify "refs/tags/$VERSION" >/dev/null || die "tag $VERSION does not exist; tag first"
if g ls-remote --exit-code --heads "$REMOTE" "$BRANCH" >/dev/null 2>&1; then
  die "$REMOTE/$BRANCH already exists"
fi

worktree="$(mktemp -d)"
cleanup() {
  g worktree remove --force "$worktree" >/dev/null 2>&1 || true
  rm -rf "$worktree"
}
trap cleanup EXIT
g branch -f "$BRANCH" "$dev_ref" >/dev/null
g worktree add --quiet "$worktree" "$BRANCH"
w() { git -C "$worktree" -c user.name="${GIT_AUTHOR_NAME:-openctem-release}" -c user.email="${GIT_AUTHOR_EMAIL:-release@openctem.invalid}" "$@"; }

if [[ "$MODE" == hotfix ]]; then
  echo "note: a hotfix needs no develop follow-up (its commits are on $DEVELOP already; no version file changes)" >&2
  exit 0
fi

if g merge-base --is-ancestor "refs/tags/$VERSION" "$dev_ref"; then
  echo "note: $VERSION is already an ancestor of $DEVELOP; nothing to merge" >&2
  exit 0
fi

# A file the tag has and develop never did would be dropped by -s ours.
# api/deploy/VERSION is the one allowed (it is written on the release branch
# only); a file develop deleted on purpose is fine.
refused=()
while IFS= read -r path; do
  [[ -n "$path" && "$path" != "$VERSION_FILE" ]] || continue
  [[ -n "$(g log -m -1 --format=%H --diff-filter=D "$dev_ref" -- "$path")" ]] || refused+=("$path")
done < <(g diff --no-renames --name-only --diff-filter=A "$dev_ref" "refs/tags/$VERSION")
if [[ ${#refused[@]} -gt 0 ]]; then
  die "$MAIN has ${#refused[@]} file(s) $DEVELOP never had (${refused[*]}); -s ours would drop them. Bring them to $DEVELOP first"
fi

w merge -s ours --no-ff --no-edit "refs/tags/$VERSION" -m "chore(release): merge $VERSION back into $DEVELOP

Makes the release tag an ancestor of $DEVELOP (it lives on $MAIN), so a pull
fetches it and the next release branch needs no -s ours. -s ours keeps
$DEVELOP's tree byte for byte: no file changes, no version is committed to
$DEVELOP." >/dev/null || die "merging $VERSION into $DEVELOP failed"
[[ "$(w rev-parse 'HEAD^{tree}')" == "$(g rev-parse "$dev_ref^{tree}")" ]] ||
  die "the merge changed $DEVELOP's tree; refusing"

HEAD_SHA="$(w rev-parse HEAD)"
if [[ $PUSH -eq 1 ]]; then
  w push --quiet "$REMOTE" "HEAD:refs/heads/$BRANCH"
  echo "pushed $BRANCH" >&2
fi
echo "BRANCH=$BRANCH"
echo "HEAD=$HEAD_SHA"
