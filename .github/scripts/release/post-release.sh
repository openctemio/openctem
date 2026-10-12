#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# post-release.sh: the follow-up branch for develop after vX.Y.Z is tagged
# (api/docs/rfcs/RFC-037 §4.2).
#
#   post-release.sh --version vX.Y.Z [--mode train|hotfix] [--chart-version X.Y.Z]
#                   [--push] [--remote origin] [--develop develop] [--main main]
#                   [--repo DIR]
#
# Builds chore/post-release-vX.Y.Z from develop with:
#   1. (train only) main merged back. main's tree is an earlier develop tree
#      plus the release branch's version commit (cut-release.sh), so the merge
#      brings exactly that: versions.yaml platform.release = vX.Y.Z and its
#      consumers. It makes main, and the tag on it, an ancestor of develop:
#      `git pull` then fetches the tag, dev builds see it (RFC-037 §3.3) and
#      the next cut needs no -s ours. A hotfix skips it: its commits are
#      already on develop, as the originals.
#   2. versions.yaml platform.release = vX.Y.Z (a no-op after a train's merge;
#      the bump itself for a hotfix) and chart.version when given, copied into
#      every consumer by sync-versions.sh.
# Refused unless the result is develop's tree plus step 2 alone: a merge that
# brings anything else means main has changes develop lacks.
#
# Prints KEY=VALUE lines: BRANCH, HEAD.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

VERSION=""
MODE="train"
CHART=""
PUSH=0
REMOTE="origin"
DEVELOP="develop"
MAIN="main"
REPO="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift ;;
    --mode) MODE="$2"; shift ;;
    --chart-version) CHART="$2"; shift ;;
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

if [[ -n "$CHART" ]]; then
  [[ "$CHART" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--chart-version must be X.Y.Z" >&2; exit 2; }
fi
# set_versions: versions.yaml platform.release = VERSION (+ chart), synced, staged.
set_versions() {
  rel_yaml_set "$worktree/versions.yaml" platform.release "$VERSION"
  [[ -z "$CHART" ]] || rel_yaml_set "$worktree/versions.yaml" chart.version "$CHART"
  bash "$HERE/sync-versions.sh" --root "$worktree" >&2 || die "versions.yaml does not sync cleanly"
  w add -A
}

# The tree develop must end up with: its own tree plus the version bump, nothing else.
set_versions
want_tree="$(w write-tree)"
w reset --quiet --hard

if [[ "$MODE" == train ]]; then
  if g merge-base --is-ancestor "refs/tags/$VERSION" "$dev_ref"; then
    echo "note: $VERSION is already an ancestor of $DEVELOP; nothing to merge" >&2
  else
    w merge --no-ff --no-edit "refs/tags/$VERSION" -m "chore(release): merge $VERSION back into $DEVELOP

Makes the release tag an ancestor of $DEVELOP (it lives on $MAIN), so a pull
fetches it and the next release branch needs no -s ours. It brings only the
release branch's version commit (versions.yaml platform.release = $VERSION):
the rest of $MAIN's tree is an earlier $DEVELOP tree." >/dev/null ||
      die "merging $VERSION into $DEVELOP conflicts; $MAIN has changes $DEVELOP lacks"
  fi
fi

set_versions
if ! w diff --cached --quiet; then
  w commit --quiet -m "chore(release): versions.yaml platform.release = $VERSION"
fi
[[ "$(w rev-parse 'HEAD^{tree}')" == "$want_tree" ]] ||
  die "merging $VERSION would change $DEVELOP beyond versions.yaml and its consumers; $MAIN has changes $DEVELOP lacks (bring them over first)"

HEAD_SHA="$(w rev-parse HEAD)"
[[ "$HEAD_SHA" != "$(g rev-parse "$dev_ref")" ]] || die "nothing to do: $DEVELOP already says $VERSION"
if [[ $PUSH -eq 1 ]]; then
  w push --quiet "$REMOTE" "HEAD:refs/heads/$BRANCH"
  echo "pushed $BRANCH" >&2
fi
echo "BRANCH=$BRANCH"
echo "HEAD=$HEAD_SHA"
