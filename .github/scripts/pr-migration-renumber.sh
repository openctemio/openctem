#!/usr/bin/env bash
# pr-migration-renumber.sh [base-commit]
#
# Pull-request CI only. Renumbers, IN THIS RUNNER'S WORKING TREE, the
# migrations a pull request adds when their versions clash with its base, so
# the tests run against the tree the merge queue will actually merge.
#
# Why: parallel pull requests each take "highest + 1". Whenever develop moves
# on, the PR's test merge (refs/pull/N/merge, what CI checks out) holds two
# migrations with one version, or one below the base's highest, and
# golang-migrate refuses to start, so every DB-backed job fails although
# nothing in the PR is wrong. Before a PR is queued its migrations are
# renumbered above develop and every queued PR, and tests find migrations by
# name (testdb.MigrationVersion), so a stale number on an open PR is not a
# defect; it only has to stop breaking the PR's CI.
#
# What it does, relative to the base commit (default HEAD^1, the base side of
# the test merge commit):
#   - an added migration whose up and down files are byte-identical to a base
#     migration of the same name (a stacked PR's copy of a migration that has
#     merged under another number) is removed;
#   - if any remaining added version is at or below the base's highest, or two
#     added migrations share a version, every added migration is renumbered,
#     in its current order, to base max + 1, + 2, ... (same digit width), and
#     references to the old file stems outside api/migrations are rewritten.
# A migration baseline (NNNNNN_baseline, RFC-053) is left alone.
# MIGRATION_TAKEN="3402 3405 ...": versions other open pull requests add (above
# the base, so the base cannot show them). An added version in that list also
# counts as a clash, and new versions start above the highest of them, so two
# renumbered pull requests never take the same number
# (api/scripts/migration-number.sh fills it from the open pull requests).
# Nothing is committed or pushed; every change is printed as a warning.
# merge_group and push never call this: there, check-migration-versions.sh
# fails a clash, which is what guards develop.
#
# Tests: .github/scripts/pr-migration-renumber.test.sh
set -euo pipefail

dir="${MIGRATIONS_DIR:-api/migrations}"
base="${1:-HEAD^1}"
pattern='^([0-9]+)_(.+)\.(up|down)\.sql$'

if ! git rev-parse -q --verify "${base}^{commit}" >/dev/null; then
  echo "::notice::pr-migration-renumber: base ${base} is not available; migrations left as they are"
  exit 0
fi

# versions: "version name raw" per migration, numerically sorted, unique.
versions() {
  local f
  while IFS= read -r f; do
    f="${f##*/}"
    if [[ "$f" =~ $pattern ]]; then echo "$((10#${BASH_REMATCH[1]})) ${BASH_REMATCH[2]} ${BASH_REMATCH[1]}"; fi
  done | sort -n -k1,1 -k2 | uniq
}

base_list="$(git ls-tree --name-only "$base" -- "$dir/" | versions)"
base_max="$(awk 'END {print ($1 == "" ? 0 : $1)}' <<<"$base_list")"
width="$(awk 'END {print ($3 == "" ? 6 : length($3))}' <<<"$base_list")"
added="$(git diff --no-renames --name-only --diff-filter=A "$base" HEAD -- "$dir/" | versions)"

# 1. Byte-identical copies of a base migration (same name, other number).
own=()
while read -r v name raw; do
  [[ -n "$v" ]] || continue
  b_raw="$(awk -v n="$name" '$2 == n {print $3; exit}' <<<"$base_list")"
  if [[ -n "$b_raw" && "$b_raw" != "$raw" ]] \
    && cmp -s "$dir/${raw}_${name}.up.sql" <(git show "${base}:${dir}/${b_raw}_${name}.up.sql" 2>/dev/null) \
    && cmp -s "$dir/${raw}_${name}.down.sql" <(git show "${base}:${dir}/${b_raw}_${name}.down.sql" 2>/dev/null); then
    rm -f "$dir/${raw}_${name}.up.sql" "$dir/${raw}_${name}.down.sql"
    echo "::warning::${dir}/${raw}_${name} is a copy of ${b_raw}_${name}, already on the base; ignored in this run"
    continue
  fi
  own+=("$v $name $raw")
done <<<"$added"

# 2. Clashes: at or below the base max, a version two added migrations share,
# or a version another open pull request takes (MIGRATION_TAKEN).
lowest="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | versions | awk 'NR == 1 {print $1}')"
taken=" " taken_max=0
for t in ${MIGRATION_TAKEN:-}; do
  t=$((10#$t)); taken+="$t "
  (( t > taken_max )) && taken_max=$t
done
need=0 seen=" "
for e in "${own[@]}"; do
  read -r v name raw <<<"$e"
  if [[ "$name" == baseline && "$v" == "$lowest" ]]; then continue; fi
  if (( v <= base_max )) || [[ "$seen" == *" $v "* || "$taken" == *" $v "* ]]; then need=1; fi
  seen+="$v "
done
if (( ! need )); then
  echo "pr-migration-renumber: no clash with the base (highest ${base_max}) or another open pull request"
  exit 0
fi

next=$(( base_max > taken_max ? base_max : taken_max ))
for e in "${own[@]}"; do
  read -r v name raw <<<"$e"
  if [[ "$name" == baseline && "$v" == "$lowest" ]]; then continue; fi
  next=$((next + 1))
  new="$(printf '%0*d' "$width" "$next")"
  [[ "$new" == "$raw" ]] && continue
  for kind in up down; do
    [[ -e "$dir/${raw}_${name}.${kind}.sql" ]] && mv "$dir/${raw}_${name}.${kind}.sql" "$dir/${new}_${name}.${kind}.sql"
  done
  # References to the old file stem (tests, docs): the same rewrite the
  # queue-time renumber makes.
  { git grep -lF "${raw}_${name}" -- . ":!${dir}/" || true; } | while IFS= read -r ref; do
    sed -i "s/${raw}_${name}/${new}_${name}/g" "$ref"
  done
  echo "::warning::${dir}/${raw}_${name} renumbered to ${new} for this run (the base is at ${base_max}); the merge queue renumbers it for real"
done
