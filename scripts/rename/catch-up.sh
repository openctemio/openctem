#!/usr/bin/env bash
# =============================================================================
# catch-up.sh: bring a branch that was opened before the api/ -> server/ rename
# (research/414) up to date with develop. Run it on your feature branch, from
# anywhere inside the clone, with a clean working tree:
#
#     git fetch origin && bash <(git show origin/develop:scripts/rename/catch-up.sh)
#
# (or `bash scripts/rename/catch-up.sh` once your branch already has it).
#
# What it does, in order:
#   1. refuses to run unless origin/develop already has server/go.mod;
#   2. takes backend-dir.sh and its patches out of origin/develop (your branch
#      may not have them) and applies them to YOUR branch: files you added
#      under api/ move to server/, your imports, ldflags and path references are
#      rewritten, gofmt re-sorts the import blocks. One commit. The same
#      mechanical change is already on develop, so identical lines do not
#      conflict in step 3;
#   3. merges origin/develop (git merge, never a rebase: a force-push drops the
#      security ack and the review threads);
#   4. runs the same rewrite once more to catch anything the merge brought in
#      under the old name, and commits it if it changed something.
#
# Re-runnable: on a branch that is already caught up it only merges develop
# when it is behind and otherwise changes nothing. If the merge in step 3
# stops on conflicts, resolve them, commit, and run the script again.
#
# If you changed server/proto yourself, run `make -C server proto` afterwards.
# Needs Go and, for the web checks, web/node_modules (npm ci). Afterwards rerun the tests of the packages you touched: a clean textual merge
# is not proof the code still builds. Environment: BASE (default origin/develop),
# VERIFY=1 runs `go build ./...` in server/ at the end.
# =============================================================================
set -euo pipefail

BASE="${BASE:-origin/develop}"
REMOTE="${BASE%%/*}"
BASE_BRANCH="${BASE#*/}"
export GOWORK=off

top="$(git rev-parse --show-toplevel)"
cd "$top"

if [ -e "$(git rev-parse --git-dir)/MERGE_HEAD" ]; then
  echo "catch-up: a merge is in progress. Resolve the conflicts, commit, then run this script again." >&2
  exit 1
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "catch-up: the working tree has uncommitted changes. Commit or stash them first." >&2
  exit 1
fi

# BASE may also be a local branch (BASE=some-branch): then there is nothing to fetch.
if git remote get-url "$REMOTE" >/dev/null 2>&1; then git fetch -q "$REMOTE" "$BASE_BRANCH"; fi
if ! git cat-file -e "$BASE:server/go.mod" 2>/dev/null; then
  echo "catch-up: $BASE has no server/go.mod: develop is not renamed yet, nothing to do." >&2
  exit 2
fi

tools="$(mktemp -d)"
trap 'find "$tools" -delete 2>/dev/null || true' EXIT
git archive "$BASE" scripts/rename | tar -x -C "$tools"
# The contract files (OpenAPI spec, route map, web types) are regenerated for the
# new module path before each commit: the commit hook type-checks the web app
# against them. The protobuf code comes from develop with the merge.
export REPO_ROOT="$top" RENAME_DIR="$tools/scripts/rename" SKIP_PROTO=1

normalise() { # <commit message>
  bash "$RENAME_DIR/backend-dir.sh"
  git add -u
  if git diff --cached --quiet; then
    echo "catch-up: nothing to rewrite"
  else
    git commit -q -s -m "$1"
    echo "catch-up: committed: $1"
  fi
}

echo "catch-up: 1/3 applying the rename to this branch"
normalise "chore: apply the api/ to server/ rename to this branch"

if git merge-base --is-ancestor "$BASE" HEAD; then
  echo "catch-up: 2/3 already contains $BASE"
else
  echo "catch-up: 2/3 merging $BASE"
  if ! git merge --no-edit -q "$BASE"; then
    echo "catch-up: the merge stopped on conflicts. Resolve them (git status), git commit, then run catch-up.sh again." >&2
    exit 1
  fi
fi

echo "catch-up: 3/3 checking for strays the merge brought in"
normalise "chore: move files that still named api/ to server/"

if [ "${VERIFY:-0}" = 1 ]; then
  echo "catch-up: go build ./... in server/"
  (cd server && go build ./...)
fi
echo "catch-up: done. Rerun the tests of the packages you touched, then push (a normal push, no force)."
