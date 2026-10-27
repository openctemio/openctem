#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# release-provenance.sh: is this pull request a release whose content was
# already gated on develop? Exit 0 and print the reason when it is; exit 1
# (printing why not on stderr) otherwise, and the caller runs the full tier.
# Called by changed.sh on pull_request. Writes nothing.
#
# What a release PR is (cut-release.sh): head `release/vX.Y.Z` into `main`, same
# repository, built in one of two shapes.
#   train    HEAD = `merge -s ours main` of the version commit V, V's parent is a
#            develop commit D. HEAD and V have the same tree.
#   hotfix   HEAD = the version commit V on top of cherry-picks (-x) of develop
#            commits, on top of the last release tag.
# Verified means ALL of:
#   - train: D is on develop and every required check of D passed (check-ci.sh:
#     the push/merge-queue runs); hotfix: the base is the newest release tag, its
#     tree is main's, and every pick has the same patch-id as a develop commit
#     that is on develop and whose containing develop commit passed its checks;
#   - V changes only the one file the release train writes (api/deploy/VERSION,
#     see release/cut-release.sh) and sets it to X.Y.Z.
# Anything else (an extra commit, a file outside the list, a red or unknown
# commit, an API error) is "not verified" and the PR runs the full tier.
#
# Env: GITHUB_EVENT_NAME, GITHUB_BASE_REF, HEAD_SHA, GITHUB_REPOSITORY, GH_TOKEN
# (checks: read), GITHUB_EVENT_PATH (head ref and repository). Tests may set
# HEAD_REF, HEAD_REPO, BASE_REPO instead of the event file.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release/lib.sh
source "$HERE/release/lib.sh"

no() { echo "release-provenance: not verified: $*" >&2; exit 1; }

# Version-train file: the version commit may touch this and nothing else.
allowed() {
  [[ "$1" == "$VERSION_FILE" ]]
}

[[ "${GITHUB_EVENT_NAME:-}" == pull_request ]] || exit 1
[[ "${GITHUB_BASE_REF:-}" == main ]] || exit 1 # an ordinary PR: silent
ev="${GITHUB_EVENT_PATH:-}"
ev_get() { if [[ -n "$ev" && -f "$ev" ]]; then jq -r "$1 // empty" "$ev" 2>/dev/null || true; fi; }
head_ref="${HEAD_REF:-$(ev_get .pull_request.head.ref)}"
[[ "$head_ref" =~ ^release/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1 # an ordinary PR: silent
head_repo="${HEAD_REPO:-$(ev_get .pull_request.head.repo.full_name)}"
base_repo="${BASE_REPO:-$(ev_get .pull_request.base.repo.full_name)}"
[[ -n "$head_repo" && "$head_repo" == "$base_repo" ]] || no "head is not in this repository"
version="${head_ref#release/}"
rel_is_version "$version" || no "bad version in the branch name"

head="${HEAD_SHA:-}"
if [[ -z "$head" ]] || ! git cat-file -e "${head}^{commit}" 2>/dev/null; then no "head commit not available"; fi
git fetch --quiet --tags origin develop main >/dev/null 2>&1 || no "cannot fetch develop, main and tags"
git rev-parse -q --verify refs/remotes/origin/develop >/dev/null || no "no origin/develop"

# develop_green SHA: SHA is on develop and every required check of it passed.
develop_green() {
  git merge-base --is-ancestor "$1" refs/remotes/origin/develop || { echo "$1 is not on develop" >&2; return 1; }
  bash "$HERE/release/check-ci.sh" "$1" >/dev/null 2>&1 || { echo "$1 is not green" >&2; return 1; }
}

# version_commit_ok V PARENT: V sets api/deploy/VERSION, touching nothing else.
version_commit_ok() {
  local v="$1" parent="$2" f got
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    allowed "$f" || no "the version commit changes $f"
  done < <(git diff --name-only --no-renames "$parent" "$v")
  got="$(git show "$v:$VERSION_FILE" 2>/dev/null | tr -d '[:space:]')" || got=""
  [[ "$got" == "$version" ]] || no "$VERSION_FILE is '$got', not $version"
}

read -r -a parents <<<"$(git rev-list --parents -n 1 "$head" | cut -d' ' -f2-)"
if [[ ${#parents[@]} -eq 2 ]]; then
  v="${parents[0]}"
  [[ "$(git rev-parse "${head}^{tree}")" == "$(git rev-parse "${v}^{tree}")" ]] || no "the merge commit changes the tree"
  git merge-base --is-ancestor "${parents[1]}" refs/remotes/origin/main || no "second parent is not on main"
  read -r -a vp <<<"$(git rev-list --parents -n 1 "$v" | cut -d' ' -f2-)"
  [[ ${#vp[@]} -eq 1 ]] || no "the version commit is not a single-parent commit"
  d="${vp[0]}"
  develop_green "$d" || no "the develop commit ${d:0:12}"
  version_commit_ok "$v" "$d"
  echo "release ${version} is develop ${d:0:12} (every required check passed) plus the version commit ${v:0:12}"
  exit 0
fi

[[ ${#parents[@]} -eq 1 ]] || no "unexpected merge shape"
last="$(rel_latest_tag .)"
[[ -n "$last" ]] || no "no release tag"
[[ "$(git rev-parse "${last}^{tree}")" == "$(git rev-parse "refs/remotes/origin/main^{tree}")" ]] || no "main has moved since $last"
[[ "$(rel_next_version "$last" patch)" == "$version" ]] || no "a hotfix of $last is $(rel_next_version "$last" patch)"
git merge-base --is-ancestor "$last" "$head" || no "$last is not an ancestor of the head"
mapfile -t chain < <(git rev-list --first-parent --reverse "${last}..${head}")
[[ ${#chain[@]} -ge 1 ]] || no "no commits after $last"
picks=0
for c in "${chain[@]}"; do
  [[ "$(git rev-list --parents -n 1 "$c" | wc -w)" -eq 2 ]] || no "${c:0:12} is not a single-parent commit"
  if [[ "$c" == "$head" ]]; then
    version_commit_ok "$c" "${c}^"
    continue
  fi
  x="$(git log -1 --format=%B "$c" | sed -nE 's/^\(cherry picked from commit ([0-9a-f]{40})\)$/\1/p' | tail -n 1)"
  [[ -n "$x" ]] || no "${c:0:12} is not a cherry-pick -x"
  git cat-file -e "${x}^{commit}" 2>/dev/null || no "pick source ${x:0:12} not found"
  pc="$(git show --format= --patch "$c" | git patch-id --stable | cut -d' ' -f1)"
  px="$(git show --format= --patch "$x" | git patch-id --stable | cut -d' ' -f1)"
  [[ -n "$pc" && "$pc" == "$px" ]] || no "${c:0:12} differs from the develop commit ${x:0:12}"
  # The develop commit (first-parent) that brought X in must have passed its checks.
  contain="" older=0
  while IFS= read -r s; do
    if git merge-base --is-ancestor "$x" "$s"; then contain="$s"; else older=1; break; fi
  done < <(git rev-list --first-parent -n 400 refs/remotes/origin/develop)
  [[ -n "$contain" && "$older" == 1 ]] || no "cannot find the develop commit that contains ${x:0:12}"
  develop_green "$contain" || no "the develop commit ${contain:0:12} holding ${x:0:12}"
  picks=$((picks + 1))
done
echo "hotfix ${version} is ${last} plus ${picks} cherry-pick(s) of green develop commits plus the version commit"
exit 0
