#!/usr/bin/env bash
# check-next-no-migrations.sh: next (the long-lived integration branch of the
# redesigned web console) takes no database migrations of its own.
#
# Rule (server/docs/development/ci-cd.md, "next integration branch"): schema
# changes land on develop, additive only, and reach next through the
# develop -> next sync pull request. So in a pull request into next, or a merge
# group for next, every changed path under server/migrations/ must be exactly
# develop's version of that path (same blob; absent on both counts as equal).
# A migration added, edited or removed on next alone fails. A sync pull request
# that brings develop's merged migrations passes, because merged migrations
# never change on develop (check-migration-versions.sh).
#
# Why: next merges into develop as one replacement merge, and rollback is a
# revert of that merge. That only works when the merge changes no schema.
#
# Env: EVENT (github.event_name), BASE_REF (github.base_ref, pull_request),
#      MG_BASE_REF (github.event.merge_group.base_ref, refs/heads/<branch>),
#      MG_BASE, MG_HEAD (merge_group.base_sha / head_sha),
#      DEVELOP (default origin/develop; tests override it).
# Any other event, or a target other than next, passes without looking.
# Unknown inputs on a next target fail (the check never waves a change through).
set -euo pipefail

target=""
case "${EVENT:-}" in
  pull_request) target="${BASE_REF:-}" ;;
  merge_group) target="${MG_BASE_REF:-}"; target="${target#refs/heads/}" ;;
  *) echo "no-migrations-on-next: ${EVENT:-no event}, nothing to check"; exit 0 ;;
esac
if [[ "$target" != next ]]; then
  echo "no-migrations-on-next: target ${target:-unknown} is not next, nothing to check"
  exit 0
fi

develop="${DEVELOP:-origin/develop}"
if [[ "$develop" == origin/develop ]]; then
  git fetch --no-tags --quiet origin develop || true
fi
git rev-parse --verify --quiet "${develop}^{commit}" >/dev/null || {
  echo "::error::no-migrations-on-next: cannot read ${develop}"; exit 1; }

if [[ "$EVENT" == pull_request ]]; then
  git rev-parse --verify --quiet origin/next >/dev/null || git fetch --no-tags --quiet origin next || true
  base="$(git merge-base origin/next HEAD)" || { echo "::error::no-migrations-on-next: no merge base with origin/next"; exit 1; }
  head=HEAD
else
  base="${MG_BASE:-}" head="${MG_HEAD:-}"
  [[ "$base" =~ ^[0-9a-f]{40}$ && "$head" =~ ^[0-9a-f]{40}$ ]] || {
    echo "::error::no-migrations-on-next: merge_group without base_sha/head_sha"; exit 1; }
fi

blob() { git rev-parse --verify --quiet "$1:$2" 2>/dev/null || echo absent; }

bad=()
while IFS= read -r -d '' path; do
  [[ "$(blob "$head" "$path")" == "$(blob "$develop" "$path")" ]] || bad+=("$path")
done < <(git diff -z --no-renames --name-only "$base" "$head" -- server/migrations/)

if [[ ${#bad[@]} -eq 0 ]]; then
  echo "no-migrations-on-next: every changed migration path equals develop's (or none changed)"
  exit 0
fi
for p in "${bad[@]}"; do
  echo "::error file=${p}::next takes no database migrations: ${p} differs from develop."
done
echo "::error::Schema changes land on develop (additive only) and reach next through the develop -> next sync pull request. Move the migration to a pull request into develop; keep only the code that uses it here."
exit 1
