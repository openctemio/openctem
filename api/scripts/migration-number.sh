#!/usr/bin/env bash
# migration-number.sh new <name> | renumber
#
# Picks migration version numbers that do not collide, so nobody chooses one
# by hand.
#
#   new <name>   creates api/migrations/<N>_<name>.{up,down}.sql with N one
#                above the highest version on origin/develop, in this branch,
#                and in every open pull request against develop.
#   renumber     moves this branch's own new migrations above all of those
#                (in their order; references to the old file names follow),
#                and stages the renames. Review, stage any rewritten
#                reference, and commit it yourself.
#
# Open pull requests are read with `gh` (skipped with a warning when gh is
# missing or not signed in: then only develop and this branch count, and the
# merge queue still renumbers at queue time). Tests find migrations by name
# (testdb.MigrationVersion), so a renumber never needs a test change.
# The rules behind it: .github/scripts/pr-migration-renumber.sh (also run by
# pull request CI on its test merge) and check-migration-versions.sh (which
# fails the merge queue on a version at or below develop's highest).
# Make targets: `make -C api migration-new name=...`, `make -C api migration-renumber`.
set -euo pipefail

top="$(git rev-parse --show-toplevel)"
cd "$top"
dir=api/migrations
repo="${MIGRATION_REPO:-openctemio/openctem}"

git fetch -q origin develop

# Versions the open pull requests (other than this branch's) add.
taken_by_prs() {
  local me
  me="$(git rev-parse --abbrev-ref HEAD)"
  # Every open pull request, stacked ones too: a stacked PR targets its parent
  # branch, not develop, and its own migrations would otherwise be missed.
  if ! command -v gh >/dev/null 2>&1 || ! gh auth status >/dev/null 2>&1; then
    echo "migration-number: gh is not available; open pull requests are not considered" >&2
    return 0
  fi
  gh pr list -R "$repo" --state open --limit 200 --json headRefName,files \
    --jq ".[] | select(.headRefName != \"$me\") | .files[].path" \
    | sed -nE "s#^${dir}/0*([0-9]+)_.*\\.up\\.sql\$#\\1#p" | sort -n | uniq | tr '\n' ' '
}

highest() { # highest <listing of file names>
  sed -nE 's#^(.*/)?0*([0-9]+)_.*\.up\.sql$#\2#p' | sort -n | tail -1
}

case "${1:-}" in
  new)
    name="${2:-}"
    [[ "$name" =~ ^[a-z0-9_]+$ ]] || { echo "usage: $0 new <snake_case_name>" >&2; exit 2; }
    dev="$(git ls-tree --name-only origin/develop -- "$dir/" | highest)"
    mine="$(find "$dir" -maxdepth 1 -name '*.up.sql' | highest)"
    prs="$(taken_by_prs | tr ' ' '\n' | sort -n | tail -1)"
    width="$(git ls-tree --name-only origin/develop -- "$dir/" | sed -nE 's#^.*/([0-9]+)_.*#\1#p' | tail -1 | awk '{print length($0)}')"
    n=0
    for v in "${dev:-0}" "${mine:-0}" "${prs:-0}"; do (( 10#$v > n )) && n=$((10#$v)); done
    stem="$(printf '%0*d' "${width:-6}" $((n + 1)))_${name}"
    for kind in up down; do
      [[ -e "$dir/${stem}.${kind}.sql" ]] && { echo "$dir/${stem}.${kind}.sql exists" >&2; exit 1; }
      printf -- '-- %s\n' "$name ($kind)" > "$dir/${stem}.${kind}.sql"
    done
    echo "created $dir/${stem}.up.sql and .down.sql (develop ${dev:-0}, this branch ${mine:-0}, open PRs ${prs:-none})"
    ;;
  renumber)
    # A branch behind develop would see develop's removed or squashed
    # migrations as "added" and rename applied files: refuse until it is
    # merged with develop.
    git merge-base --is-ancestor origin/develop HEAD || {
      echo "merge origin/develop into this branch first (git fetch origin develop && git merge origin/develop)" >&2
      exit 1
    }
    MIGRATION_TAKEN="$(taken_by_prs)" bash .github/scripts/pr-migration-renumber.sh origin/develop
    # Stage the renames; files whose references were rewritten show as
    # modified: review and stage them with the renames, then commit.
    git add -A -- "$dir"
    git status --short
    ;;
  *)
    sed -n '2,13p' "$0" >&2
    exit 2
    ;;
esac
