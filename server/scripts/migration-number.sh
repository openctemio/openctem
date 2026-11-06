#!/usr/bin/env bash
# migration-number.sh new <name> | renumber
#
# Migration versions are UTC timestamps (YYYYMMDDHHMMSS) and only have to be
# unique: openctem-migrate applies every migration a database has not
# applied, whatever its version (docs/rfcs/RFC-130-migration-applied-set.md).
#
#   new <name>   creates api/migrations/<UTC now>_<name>.{up,down}.sql (one
#                second later while that version is taken).
#   renumber     gives this branch's added migrations new timestamp versions
#                when a version is also used by develop or an open pull
#                request, or is still a legacy sequential number; the ones
#                after it move too, in order. References to the old file
#                names follow, and the renames are staged. Review, stage any
#                rewritten reference, and commit it yourself.
#
# Open pull requests are read with `gh` for renumber (skipped with a warning
# when gh is missing or not signed in). Tests find migrations by name
# (testdb.MigrationVersion), so a new version never needs a test change.
# The rules behind it: .github/scripts/pr-migration-renumber.sh (also run by
# pull request CI on its test merge) and check-migration-versions.sh.
# Make targets: `make -C api migration-new name=...`, `make -C api migration-renumber`.
set -euo pipefail

top="$(git rev-parse --show-toplevel)"
cd "$top"
dir=api/migrations
repo="${MIGRATION_REPO:-openctemio/openctem}"


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

case "${1:-}" in
  new)
    name="${2:-}"
    [[ "$name" =~ ^[a-z0-9_]+$ ]] || { echo "usage: $0 new <snake_case_name>" >&2; exit 2; }
    stamp_of() { date -u -d "@$1" +%Y%m%d%H%M%S 2>/dev/null || date -u -r "$1" +%Y%m%d%H%M%S; }
    epoch="$(date -u +%s)"
    while :; do
      v="$(stamp_of "$epoch")"
      compgen -G "$dir/${v}_*" >/dev/null || break
      epoch=$((epoch + 1))
    done
    stem="${v}_${name}"
    for kind in up down; do
      printf -- '-- %s\n' "$name ($kind)" > "$dir/${stem}.${kind}.sql"
    done
    echo "created $dir/${stem}.up.sql and .down.sql"
    ;;
  renumber)
    git fetch -q origin develop
    # A branch behind develop would see develop's removed or squashed
    # migrations as "added" and rename applied files: refuse until it is
    # merged with develop.
    git merge-base --is-ancestor origin/develop HEAD || {
      echo "merge origin/develop into this branch first (git fetch origin develop && git merge origin/develop)" >&2
      exit 1
    }
    MIGRATION_TAKEN="$(taken_by_prs)" MIGRATION_RENUMBER_LEGACY=1 bash .github/scripts/pr-migration-renumber.sh origin/develop
    # Stage the renames; files whose references were rewritten show as
    # modified: review and stage them with the renames, then commit.
    git add -A -- "$dir"
    git status --short
    ;;
  *)
    sed -n '2,16p' "$0" >&2
    exit 2
    ;;
esac
