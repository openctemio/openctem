#!/usr/bin/env bash
# precheck.sh [--verify]: run before a push (`make precheck`).
#
# 1. Sync with the branch its pull request targets (BASE, else the open PR's
#    base, else origin/develop). A branch not pushed yet is rebased onto it.
#    A branch already on the remote is merged with it ONLY when the two
#    conflict: a clean "merge develop" commit re-runs the whole CI for nothing
#    (the merge queue tests every PR on top of the newest develop anyway), and
#    89 of 164 such commits on 2026-10-23..25 had no conflict. The i18n
#    catalog merge driver is set up first. A conflict that the merge cannot
#    resolve stops here: resolve it locally, never in the pull request.
#    It then warns about other open pull requests that touch the same files.
# 2. Checks: what CI's lint and static gates check, for the components the
#    branch changes. API: gofmt, go vet, staticcheck, golangci-lint on new
#    code (`make -C api lint-ci`). Web: prettier, eslint on changed files,
#    tsc, the separator gate and sorted message catalogs.
#
# --verify (the pre-push hook): never changes the branch; fails when a branch
# not pushed yet is behind its base, or a pushed one conflicts with it, and
# tells you to run `make precheck`.
set -euo pipefail
top=$(git rev-parse --show-toplevel)
cd "$top"
verify=0
[ "${1:-}" = "--verify" ] && verify=1
branch=$(git rev-parse --abbrev-ref HEAD)
repo=${REPO:-openctemio/openctem}

if [ -z "${BASE:-}" ] && command -v gh >/dev/null 2>&1; then
  prbase=$(gh pr view "$branch" -R "$repo" --json baseRefName,state -q 'select(.state=="OPEN")|.baseRefName' 2>/dev/null || true)
  [ -n "$prbase" ] && BASE="origin/$prbase"
fi
base=${BASE:-origin/develop}
git fetch -q origin "${base#origin/}"

git config merge.i18n-json.name >/dev/null 2>&1 || {
  git config merge.i18n-json.name "i18n catalogs, merged key by key"
  git config merge.i18n-json.driver "node web/scripts/i18n-json.mjs merge %O %A %B %P"
}

pushed=0
git rev-parse --verify -q "origin/$branch" >/dev/null && pushed=1
need_sync=0
if ! git merge-base --is-ancestor "$base" HEAD; then
  need_sync=1
  # A pushed branch that merges cleanly stays as it is (see 1. above). The
  # merge-tree run writes objects only, never the branch or the work tree.
  if [ "$pushed" = 1 ] && git merge-tree --write-tree HEAD "$base" >/dev/null 2>&1; then
    echo "precheck: $branch is behind $base but merges cleanly; not merging (the merge queue tests it on top of $base)"
    need_sync=0
  fi
fi
if [ "$need_sync" = 1 ]; then
  if [ "$verify" = 1 ]; then
    if [ "$pushed" = 1 ]; then
      echo "pre-push: $branch conflicts with $base. Run: make precheck (it merges, then checks)"
    else
      echo "pre-push: $branch is behind $base. Run: make precheck (it rebases, then checks)"
    fi
    exit 1
  fi
  if [ "$pushed" = 1 ]; then
    echo "precheck: $branch conflicts with $base; merging $base into $branch"
    git merge --no-edit "$base" || { git merge --abort; echo "precheck: conflict with $base; resolve it locally (git merge $base), then run make precheck again"; exit 1; }
  else
    echo "precheck: rebasing $branch onto $base"
    git rebase "$base" || { git rebase --abort; echo "precheck: conflict with $base; resolve it locally (git rebase $base), then run make precheck again"; exit 1; }
  fi
  if git diff --name-only "HEAD@{1}" HEAD 2>/dev/null | grep -q '^web/src/lib/i18n/dictionaries/'; then
    node web/scripts/i18n-json.mjs sort
    git diff --quiet || git commit -qam "chore(i18n): sort catalogs after syncing with ${base#origin/}"
  fi
fi

changed=$(git diff --name-only --diff-filter=ACMR "$(git merge-base "$base" HEAD)" HEAD)
[ -z "$changed" ] && { echo "precheck: nothing changed against $base"; exit 0; }

# Other open pull requests on the same files: they are the next conflicts.
if [ "$verify" = 0 ] && command -v gh >/dev/null 2>&1; then
  gh pr list -R "$repo" --state open --limit 200 --json number,headRefName,files \
    --jq ".[] | select(.headRefName != \"$branch\") | \"\(.number) \(.files[].path)\"" 2>/dev/null |
    awk 'NR==FNR { mine[$0]=1; next } ($2 in mine) { hit[$1]=hit[$1] " " $2 } END { for (n in hit) print "precheck: open PR #" n " also changes:" hit[n] }' \
      <(printf '%s\n' "$changed") - || true
fi

fail=0

if printf '%s\n' "$changed" | grep -q '^api/.*\.go$'; then
  echo "precheck: api"
  bad=$(printf '%s\n' "$changed" | grep '^api/.*\.go$' | xargs gofmt -l 2>/dev/null || true)
  [ -n "$bad" ] && { echo "gofmt needed:"; echo "$bad"; fail=1; }
  make -s -C api lint-ci BASE_REF="$base" || fail=1
fi

if printf '%s\n' "$changed" | grep -qE '^web/(src/|e2e/|scripts/|package(-lock)?\.json$|tsconfig[^/]*\.json$|next\.config|eslint|\.prettier)'; then
  echo "precheck: web"
  if [ ! -d web/node_modules ]; then
    echo "precheck: web/node_modules missing; run: (cd web && npm ci)"; exit 1
  fi
  # tsc needs the generated contract files (never committed).
  if [ ! -f web/src/lib/api/generated/api.types.ts ] || [ ! -f web/src/config/api-route-permissions.json ]; then
    echo "precheck: generating contract files (make generate)"
    make -s generate || fail=1
  fi
  files=$(printf '%s\n' "$changed" | grep -E '^web/src/.*\.(ts|tsx)$' | sed 's#^web/##' || true)
  (
    cd web
    if [ -n "$files" ]; then
      # shellcheck disable=SC2086
      npx --no-install prettier --check $files
      # shellcheck disable=SC2086
      npx --no-install eslint $files
    fi
    npm run -s type-check
    bash scripts/check-separators.sh "$base"
    node scripts/check-copy.mjs "$base"
    node scripts/i18n-json.mjs sort --check
  ) || fail=1
fi

[ "$fail" = 0 ] && echo "precheck: ok" || { echo "precheck: failed (fix before pushing)"; exit 1; }
