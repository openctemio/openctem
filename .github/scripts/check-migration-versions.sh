#!/usr/bin/env bash
# check-migration-versions.sh [base-commit]
#
# Guards the migration files in api/migrations (VERSION_name.{up,down}.sql).
# openctem-migrate applies every migration a database has not applied, in
# version order, whatever the highest applied version is
# (docs/rfcs/RFC-130-migration-applied-set.md). So a version only has to be
# unique, and a migration that has merged must never change:
#
#   1. No two migrations share a version: the runner refuses to start.
#      MIGRATION_DUPLICATE=warning (pull_request) reports a version this
#      change adds that the base also uses as a warning: PR CI renumbers its
#      copy for the run (pr-migration-renumber.sh) and the author runs
#      `make -C api migration-renumber`. Everywhere else it fails.
#   2. With a base commit:
#      - an added migration has a UTC timestamp version YYYYMMDDHHMMSS
#        (`make -C api migration-new`). A legacy sequential number (up to six
#        digits) is still accepted with a warning while older pull requests
#        land, but only above the base's highest legacy number and only while
#        the base has no timestamp version: when the runner takes over a
#        database the earlier tool migrated, it records every legacy-numbered
#        file up to that tool's version as applied, so a lower one would
#        never run there (on pull_request this case is a warning too: PR CI
#        and `make -C api migration-renumber` move it to a timestamp), and
#        once a timestamp version has merged that tool's version may be a
#        timestamp, above every legacy number (always an error). Any other
#        form fails;
#      - no up file of the base is changed, removed or renamed: databases
#        that applied it would never see the change (or would re-run it under
#        a new version). A fix is a new migration. One exception: a migration
#        baseline (NNNNNN_baseline, RFC-053) added as the lowest version
#        replaces, and so removes, the files up to its version.
#      Down files may be fixed: they run only on a rollback.
#
# Base commit: the PR's base branch on pull_request, merge_group.base_sha in the
# merge queue, develop before the push on a push to develop, none otherwise
# (only check 1). Run from the repository root.
#
# Tests: .github/scripts/check-migration-versions.test.sh
set -euo pipefail

dir="${MIGRATIONS_DIR:-api/migrations}"
base="${1:-}"
pattern='^([0-9]+)_(.+)\.(up|down)\.sql$'
fail=0
dup_mode="${MIGRATION_DUPLICATE:-error}"
err() { echo "::error::$*"; fail=1; }
warn() { echo "::warning::$*"; }

# versions <listing> -> "version name raw" per migration file, numerically sorted.
versions() {
  local f
  while IFS= read -r f; do
    f="${f##*/}"
    if [[ "$f" =~ $pattern ]]; then echo "$((10#${BASH_REMATCH[1]})) ${BASH_REMATCH[2]} ${BASH_REMATCH[1]}"; fi
  done | sort -n -k1,1 -k2 | uniq
}

# valid_stamp YYYYMMDDHHMMSS: a real UTC time from 2026 on.
valid_stamp() {
  local s="$1"
  [[ "$s" =~ ^(20[2-9][0-9])(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9])$ ]] || return 1
  (( 10#${BASH_REMATCH[1]} >= 2026 )) || return 1
  # Day of month: the date command rejects 20260231.
  date -u -d "${s:0:8}" +%s >/dev/null 2>&1 || date -u -j -f %Y%m%d "${s:0:8}" +%s >/dev/null 2>&1
}

current="$(find "$dir" -maxdepth 1 -type f -name '*.sql' | versions)"
lowest="$(awk 'NR == 1 {print $1}' <<<"$current")"

added=""
base_legacy_max=0
base_has_stamp=0
if [[ -n "$base" ]]; then
  # --no-renames: a renamed migration shows as removed + added.
  added="$(git diff --no-renames --name-only --diff-filter=A "$base" HEAD -- "$dir/" | versions)"
  base_legacy_max="$(git ls-tree --name-only "$base" -- "$dir/" | versions | awk 'length($3) < 14 {m = $1} END {print m + 0}')"
  if git ls-tree --name-only "$base" -- "$dir/" | versions | awk 'length($3) >= 14 {f = 1} END {exit !f}'; then base_has_stamp=1; fi
fi

# 1. One name per version (the .up/.down pair share it).
dups="$(awk '{print $1}' <<<"$current" | uniq -d)"
for v in $dups; do
  names="$(awk -v v="$v" '$1 == v {print $3 "_" $2}' <<<"$current" | tr '\n' ' ')"
  mine="$(awk -v v="$v" '$1 == v' <<<"$added" | wc -l)"
  total="$(awk -v v="$v" '$1 == v' <<<"$current" | wc -l)"
  if [[ "$dup_mode" == warning && "$mine" -eq 1 && "$total" -eq 2 ]]; then
    warn "migration version $v is used more than once: ${names}- give this change's copy a new version: make -C api migration-renumber, then commit"
  else
    err "migration version $v is used more than once: ${names}- give one a new version: make -C api migration-renumber"
  fi
done

if [[ -n "$base" ]]; then
  # 2a. Version form of the added migrations.
  while read -r v name raw; do
    [[ -n "$v" ]] || continue
    if [[ "$name" == baseline ]] && (( v == lowest )); then continue; fi
    if (( ${#raw} == 14 )) && valid_stamp "$raw"; then continue; fi
    if (( ${#raw} <= 6 )) && (( base_has_stamp )); then
      err "$dir/${raw}_${name} has the sequential version $v, but the base already has timestamp versions: a database the earlier tool migrated to a timestamp version would record it as applied without running it. Renumber with make -C api migration-renumber, then commit."
    elif (( ${#raw} <= 6 )) && (( v <= base_legacy_max )); then
      msg="$dir/${raw}_${name} has the sequential version $v, at or below the base's highest ($base_legacy_max): a database the earlier tool migrated past it would record it as applied without running it. Give it a timestamp version: make -C api migration-renumber, then commit."
      if [[ "$dup_mode" == warning ]]; then warn "$msg"; else err "$msg"; fi
    elif (( ${#raw} <= 6 )); then
      warn "$dir/${raw}_${name} has a sequential version. New migrations take a timestamp version (make -C api migration-new name=...); move it with make -C api migration-renumber."
    else
      err "$dir/${raw}_${name}: the version must be a UTC timestamp YYYYMMDDHHMMSS. Create migrations with make -C api migration-new name=..., or move this one with make -C api migration-renumber."
    fi
  done <<<"$added"

  # 2b. Merged up files never change.
  baseline_added=""
  while read -r v name raw; do
    [[ "$name" == baseline && -n "$v" ]] && (( v == lowest )) && baseline_added="$v"
  done <<<"$added"
  while IFS=$'\t' read -r status path; do
    [[ -n "$status" ]] || continue
    f="${path##*/}"
    [[ "$f" =~ $pattern && "${BASH_REMATCH[3]}" == up ]] || continue
    v=$((10#${BASH_REMATCH[1]}))
    if [[ "$status" == D && -n "$baseline_added" ]] && (( v <= baseline_added )); then continue; fi
    case "$status" in
      M) what="changed" ;;
      D) what="removed or renamed" ;;
      *) what="changed ($status)" ;;
    esac
    err "$path is $what, but it has merged: databases that applied it never run it again. Revert that and put the change in a new migration (make -C api migration-new name=...)."
  done < <(git diff --no-renames --name-status --diff-filter=MDT "$base" HEAD -- "$dir/")
  echo "base $base: added: $(awk '{printf "%s_%s ", $3, $2}' <<<"$added")"
fi

if (( fail )); then exit 1; fi
echo "migration versions OK ($(wc -l <<<"$current" | tr -d ' ') distinct)"
