#!/usr/bin/env bash
#
# check-migrations.sh — guard against deploy-breaking (non-expand-contract)
# schema changes in new database migrations.
#
# WHY: production runs a zero-downtime ROLLING deploy. During a rollout the OLD
# app pods keep serving traffic against the NEW schema for a short window. A
# destructive migration (DROP COLUMN, RENAME, incompatible type change, adding a
# NOT NULL column without a default, ...) applied in that window makes the still
# running old pods 500/crash — a silent partial outage. The safe pattern is
# EXPAND-CONTRACT:
#
#   release N   : ADD the new shape (nullable column / new table / new index).
#                 Backward compatible — old and new code both work.
#   release N   : deploy code that stops reading/writing the OLD shape.
#   release N+1 : REMOVE the old shape, now that nothing running references it.
#
# This script scans NEW/CHANGED migrations/*.up.sql files and FAILS when it finds
# a destructive operation, unless the migration is explicitly annotated (see
# "Override" below). It is intentionally simple and low-false-positive: it flags
# the well-known deploy-breakers and lets everything additive through.
#
# Usage:
#   scripts/check-migrations.sh                 # CI mode: diff against base branch
#   scripts/check-migrations.sh FILE [FILE...]  # scan the given files (local/tests)
#   BASE_REF=origin/develop scripts/check-migrations.sh
#
# Override (only when a destructive change is genuinely required — normally the
# N+1 "contract" step of an expand-contract pair):
#   1. Add a marker line anywhere in the .up.sql file:
#        -- expand-contract-ok: <reason, e.g. "contract step, old col unused since v0.5.0">
#   2. ...or set ALLOW_DESTRUCTIVE_MIGRATION=true. In CI this is wired to the
#      'allow-destructive-migration' pull-request label.
#
# Exit codes: 0 = clean/allowed, 1 = destructive migration found, 2 = usage error.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MARKER='expand-contract-ok'

# --- discover which .up.sql files to scan -----------------------------------

discover_from_git() {
  local base_ref="${BASE_REF:-}"
  if [ -z "$base_ref" ]; then
    if [ -n "${GITHUB_BASE_REF:-}" ]; then
      base_ref="origin/${GITHUB_BASE_REF}"
    else
      base_ref="origin/develop"
    fi
  fi

  local merge_base
  if ! merge_base="$(git -C "$REPO_ROOT" merge-base "$base_ref" HEAD 2>/dev/null)"; then
    echo "WARN: cannot find merge-base with '$base_ref'; comparing against '$base_ref' directly" >&2
    merge_base="$base_ref"
  fi

  # Added (A), Copied (C), Modified (M), Renamed (R) up-migration files.
  git -C "$REPO_ROOT" diff --name-only --diff-filter=ACMR "$merge_base" HEAD -- 'migrations/*.up.sql'
}

FILES=()
if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  while IFS= read -r f; do
    [ -n "$f" ] && FILES+=("$REPO_ROOT/$f")
  done < <(discover_from_git)
fi

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "check-migrations: no new/changed migrations/*.up.sql — nothing to check."
  exit 0
fi

if [ "${ALLOW_DESTRUCTIVE_MIGRATION:-false}" = "true" ]; then
  echo "check-migrations: ALLOW_DESTRUCTIVE_MIGRATION=true — skipping destructive check (override active)." >&2
  exit 0
fi

# --- normalise + scan one file ----------------------------------------------

# strip_sql <file> : drop `-- ...` line comments, collapse whitespace, lowercase.
strip_sql() {
  # Remove everything from an unquoted `--` to end of line, then squeeze
  # whitespace/newlines to single spaces so multi-line statements match, then
  # lowercase for case-insensitive matching.
  sed -E 's/--.*$//' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' ' | tr '[:upper:]' '[:lower:]'
}

# check_statement <stmt> : echo a reason if the statement is destructive.
check_statement() {
  local s="$1"
  case "$s" in
    *"drop table"*)  echo "DROP TABLE — removes a table other pods may still query" ;;
    *"drop column"*) echo "DROP COLUMN — old pods still SELECT/INSERT this column" ;;
    *"truncate"*)    echo "TRUNCATE — destroys data" ;;
    *)
      # ALTER COLUMN ... TYPE / SET DATA TYPE — an incompatible type rewrite.
      if printf '%s' "$s" | grep -Eq 'alter +column[^;]*(set +data +type|[[:space:]]type[[:space:]])'; then
        echo "ALTER COLUMN ... TYPE — in-place type change breaks old pods mid-rollout"
      # RENAME (column / table / constraint) — old code references the old name.
      elif printf '%s' "$s" | grep -Eq 'alter +table[^;]*rename'; then
        echo "RENAME — old pods reference the old name until they are replaced"
      # ALTER COLUMN ... SET NOT NULL — old code may still write NULL.
      elif printf '%s' "$s" | grep -Eq 'set +not +null'; then
        echo "SET NOT NULL — tightens an existing column; old writes with NULL fail"
      # ADD COLUMN ... NOT NULL without a DEFAULT — existing rows / old inserts fail.
      elif printf '%s' "$s" | grep -Eq 'add +column' \
            && printf '%s' "$s" | grep -Eq 'not +null' \
            && ! printf '%s' "$s" | grep -Eq 'default'; then
        echo "ADD COLUMN ... NOT NULL without DEFAULT — fails on existing rows / old inserts"
      fi
      ;;
  esac
}

fail=0
for file in "${FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo "check-migrations: skipping missing file: $file" >&2
    continue
  fi

  rel="${file#"$REPO_ROOT"/}"

  # Explicit per-file override marker (a comment, so read from the raw file).
  if grep -Eiq "$MARKER" "$file"; then
    reason="$(grep -Ei "$MARKER" "$file" | head -n1 | sed -E "s/.*${MARKER}:?[[:space:]]*//I")"
    if [ -z "$reason" ]; then
      echo "✗ $rel: '$MARKER' marker present but no reason given — add: -- $MARKER: <reason>" >&2
      fail=1
      continue
    fi
    echo "• $rel: destructive check waived via '$MARKER' — $reason"
    continue
  fi

  stripped="$(strip_sql "$file")"

  file_flagged=0
  # Split into statements on ';' and check each.
  while IFS= read -r stmt; do
    [ -n "$stmt" ] || continue
    reason="$(check_statement " $stmt ")"
    if [ -n "$reason" ]; then
      if [ "$file_flagged" -eq 0 ]; then
        echo "✗ $rel:" >&2
        file_flagged=1
        fail=1
      fi
      echo "    - $reason" >&2
    fi
  done < <(printf '%s' "$stripped" | tr ';' '\n')

  [ "$file_flagged" -eq 0 ] && echo "✓ $rel: no destructive operations"
done

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'EOF'

────────────────────────────────────────────────────────────────────────────
Destructive migration blocked.

Production deploys are ROLLING: old app pods run against the new schema for a
short window, so a destructive change breaks them mid-deploy. Use EXPAND-CONTRACT:

  • release N   : ADD the new shape (nullable column / new table / new index).
  • release N   : ship code that stops using the OLD shape.
  • release N+1 : REMOVE the old shape (this migration) once nothing uses it.

If this migration IS the N+1 contract step (or is otherwise safe), annotate it:

  -- expand-contract-ok: <reason, e.g. "contract step; column unused since v0.5.0">

...or apply the 'allow-destructive-migration' PR label.

See docs/deployment/safe-deploy-and-migrations.md for the full guide.
────────────────────────────────────────────────────────────────────────────
EOF
  exit 1
fi

# ────────────────────────────────────────────────────────────────────────────
# Duplicate version numbers.
#
# golang-migrate keys on the numeric prefix, so two files sharing one is not a
# style problem — the second is unreachable and `migrate up` errors out. It is
# invisible per-PR: two branches cut from the same develop each add 000200, each
# is green on its own, and the collision only exists after both merge. That is
# exactly what happened with #396 and #397, and neither CI run could have seen
# it.
#
# Checked over the whole directory, not just changed files, for the same reason.
# ────────────────────────────────────────────────────────────────────────────
dupes="$(ls migrations/*.up.sql 2>/dev/null \
  | sed -E 's#.*/([0-9]+)_.*#\1#' \
  | sort | uniq -d)"

if [[ -n "$dupes" ]]; then
  echo >&2
  echo "check-migrations: duplicate migration version(s):" >&2
  for v in $dupes; do
    echo "  $v" >&2
    ls migrations/${v}_* 2>/dev/null | sed 's/^/    /' >&2
  done
  cat >&2 <<'EOF'

golang-migrate keys on the numeric prefix. Two files sharing one means the
second never runs and `migrate up` fails. Renumber the newer one to the next
free version and update any comment that names it.

This usually happens when two branches are cut from the same base — each is
green alone and the collision only appears once both are merged.
EOF
  exit 1
fi

echo "check-migrations: all migrations are expand-contract safe, versions unique."
exit 0
