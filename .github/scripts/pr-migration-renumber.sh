#!/usr/bin/env bash
# pr-migration-renumber.sh [base-commit]
#
# Gives the migrations a change adds new, unique versions when theirs clash.
# Used by pull request CI on its test merge (in the runner's working tree
# only, never committed) and by `make -C api migration-renumber` (which
# stages the renames for the author to commit).
#
# Migration versions only have to be unique: openctem-migrate applies every
# migration a database has not applied, whatever the highest applied version
# is (docs/rfcs/RFC-130-migration-applied-set.md). A timestamp version below
# the base's highest is therefore fine and left alone. What still breaks:
#   - an added version the base also uses (two pull requests that took the
#     same legacy "next number");
#   - a version two added migrations share;
#   - a version another open pull request adds (MIGRATION_TAKEN="3402 ...");
#   - a legacy sequential number at or below the base's highest legacy one
#     (a takeover of a database the earlier tool migrated would record it as
#     applied without running it);
#   - any legacy sequential number once the base has a timestamp version
#     (that tool's version may then be a timestamp, above every legacy one).
# MIGRATION_RENUMBER_LEGACY=1 also moves added migrations that still carry a
# legacy sequential number (fewer than 14 digits) to a timestamp version.
#
# What it does, relative to the base commit (default HEAD^1, the base side of
# the test merge commit):
#   - an added migration whose up and down files are byte-identical to a base
#     migration of the same name (a stacked PR's copy of a migration that has
#     merged under another number) is removed;
#   - the first clashing added migration and every added migration above it
#     (so their order is kept) get UTC timestamp versions YYYYMMDDHHMMSS,
#     starting at the current second (MIGRATION_NOW overrides it, for tests),
#     each one unused by the base, the tree and MIGRATION_TAKEN; references
#     to the old file stems outside api/migrations are rewritten.
# A migration baseline (NNNNNN_baseline, RFC-053) is left alone.
# Nothing is committed or pushed; every change is printed as a warning.
# merge_group and push never call this: there, check-migration-versions.sh
# fails a duplicate, which is what guards develop.
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

# 2. The first clash: a version the base uses, one two added migrations
# share, one another open pull request takes, or (legacy mode) a legacy
# sequential number.
lowest="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | versions | awk 'NR == 1 {print $1}')"
used=" " legacy_max=0 base_has_stamp=0
while read -r v _ raw; do
  [[ -n "$v" ]] || continue
  used+="$v "
  (( ${#raw} < 14 && v > legacy_max )) && legacy_max=$v
  (( ${#raw} >= 14 )) && base_has_stamp=1
done <<<"$base_list"
taken=" "
for t in ${MIGRATION_TAKEN:-}; do taken+="$((10#$t)) "; done
first=-1 seen=" " i=0
for e in "${own[@]}"; do
  read -r v name raw <<<"$e"
  if ! [[ "$name" == baseline && "$v" == "$lowest" ]] && (( first < 0 )); then
    if [[ "$used" == *" $v "* || "$seen" == *" $v "* || "$taken" == *" $v "* ]] \
      || { (( ${#raw} < 14 )) && { [[ "${MIGRATION_RENUMBER_LEGACY:-}" == 1 ]] || (( base_has_stamp || v <= legacy_max )); }; }; then
      first=$i
    fi
  fi
  seen+="$v "
  i=$((i + 1))
done
if (( first < 0 )); then
  echo "pr-migration-renumber: no clash with the base or another open pull request"
  exit 0
fi

# Timestamps: GNU date, or BSD date on a developer's Mac.
epoch_of() { date -u -d "${1:0:8} ${1:8:2}:${1:10:2}:${1:12:2}" +%s 2>/dev/null || date -u -j -f %Y%m%d%H%M%S "$1" +%s; }
stamp_of() { date -u -d "@$1" +%Y%m%d%H%M%S 2>/dev/null || date -u -r "$1" +%Y%m%d%H%M%S; }
now="${MIGRATION_NOW:-$(date -u +%Y%m%d%H%M%S)}"
epoch="$(epoch_of "$now")"
in_tree=" "
while read -r v _; do [[ -n "$v" ]] && in_tree+="$v "; done < <(find "$dir" -maxdepth 1 -type f -name '*.sql' | versions)

i=0
for e in "${own[@]}"; do
  read -r v name raw <<<"$e"
  i=$((i + 1))
  (( i - 1 >= first )) || continue
  if [[ "$name" == baseline && "$v" == "$lowest" ]]; then continue; fi
  while :; do
    new="$(stamp_of "$epoch")"
    epoch=$((epoch + 1))
    [[ "$used" == *" $((10#$new)) "* || "$taken" == *" $((10#$new)) "* || "$in_tree" == *" $((10#$new)) "* ]] || break
  done
  in_tree+="$((10#$new)) "
  for kind in up down; do
    [[ -e "$dir/${raw}_${name}.${kind}.sql" ]] && mv "$dir/${raw}_${name}.${kind}.sql" "$dir/${new}_${name}.${kind}.sql"
  done
  # References to the old file stem (tests, docs).
  { git grep -lF "${raw}_${name}" -- . ":!${dir}/" || true; } | while IFS= read -r ref; do
    sed -i.bak "s/${raw}_${name}/${new}_${name}/g" "$ref" && rm -f "$ref.bak"
  done
  echo "::warning::${dir}/${raw}_${name} renumbered to ${new} (its version clashed, or follows one that did)"
done
