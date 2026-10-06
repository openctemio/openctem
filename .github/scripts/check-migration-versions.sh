#!/usr/bin/env bash
# check-migration-versions.sh [base-commit]
#
# Guards golang-migrate version numbers in api/migrations (NNNNNN_name.{up,down}.sql):
#
#   1. No two migrations share a version. Two PRs written in parallel both
#      take "max+1"; once both merge, golang-migrate refuses to start on the
#      duplicate.
#   2. With a base commit: every migration this change ADDS must have a version
#      above the highest version already on the base. golang-migrate only
#      applies versions above a database's current one, so a lower number
#      merged later is silently skipped on every already-migrated database.
#      One exception: a migration baseline (NNNNNN_baseline, RFC-053) replaces
#      the chain up to its version, so it may be at or below the base's
#      highest version, provided it is the lowest version left in the tree
#      (every migration it replaces was removed in the same change).
#
# Base commit: the PR's base branch on pull_request, merge_group.base_sha in the
# merge queue (so a queued PR is re-checked against what is actually ahead of
# it), none on push (only check 1). Run from the repository root.
#
# Tests: .github/scripts/check-migration-versions.test.sh
set -euo pipefail

dir="${MIGRATIONS_DIR:-api/migrations}"
base="${1:-}"
pattern='^([0-9]+)_(.+)\.(up|down)\.sql$'
fail=0
err() { echo "::error::$*"; fail=1; }

# versions <listing> -> "version name" per migration file, numerically sorted.
versions() {
  local f
  while IFS= read -r f; do
    f="${f##*/}"
    if [[ "$f" =~ $pattern ]]; then echo "$((10#${BASH_REMATCH[1]})) ${BASH_REMATCH[2]} ${BASH_REMATCH[1]}"; fi
  done | sort -n -k1,1 -k2 | uniq
}

current="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | versions)"
lowest="$(awk 'NR == 1 {print $1}' <<<"$current")"

# 1. One name per version (the .up/.down pair share it).
dups="$(awk '{print $1}' <<<"$current" | uniq -d)"
for v in $dups; do
  names="$(awk -v v="$v" '$1 == v {print $3 "_" $2}' <<<"$current" | tr '\n' ' ')"
  err "migration version $v is used more than once: ${names}- renumber one of them"
done

# 2. Added migrations must be above the base's highest version.
if [[ -n "$base" ]]; then
  base_list="$(git ls-tree --name-only "$base" -- "$dir/" | versions)"
  base_max="$(awk 'END {print ($1 == "" ? 0 : $1)}' <<<"$base_list")"
  # --no-renames: a file that replaces a base migration (same content under a
  # new number or name) is an addition here, not a rename to skip.
  added="$(git diff --no-renames --name-only --diff-filter=A "$base" HEAD -- "$dir/" | versions)"
  while read -r v name raw; do
    [[ -n "$v" ]] || continue
    if [[ "$name" == baseline ]] && (( v == lowest )); then
      continue
    fi
    if (( v <= base_max )); then
      next=$((base_max + 1))
      err "$dir/${raw}_${name} is version $v, but the base already has migrations up to $base_max. golang-migrate would silently skip it on every database already at $base_max. Renumber it to $(printf '%0*d' "${#raw}" "$next")."
    fi
  done <<<"$added"
  echo "base $base: highest migration version $base_max; added: $(awk '{printf "%s ", $3}' <<<"$added")"
fi

if (( fail )); then exit 1; fi
echo "migration versions OK ($(wc -l <<<"$current" | tr -d ' ') distinct)"
