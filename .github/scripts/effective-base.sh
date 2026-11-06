#!/usr/bin/env bash
# effective-base.sh <api|web> <base-ref>
#
# Prints the commit that "new code" gates (golangci-lint --new-from-rev, the
# destructive-migration guard, the palette-drift guard) should diff against.
#
# Normally that is just <base-ref>. The exception is the ONE pull request that
# turns openctemio/api into the monorepo: its base still has the Go code at the
# repository root and no web/ at all, so every file looks new, and the gates
# would re-report all pre-existing findings (golangci: 167 in the rehearsal) and
# every historical migration. For that PR only, diff against the point where
# the component arrived in its new place:
#   api -> the pure-rename commit "chore(monorepo): move the Go API into api/"
#   web -> ui's own tip, i.e. the second parent of the import merge
# The same applies to the pull request that renamed the backend directory (source
# layout only): its base still has the Go code in the old directory, so the "new
# code" gates diff against the pure-move commit "chore(rename): move api/ to
# server/" (rename-guard: allow). Once both are merged, every base has
# server/go.mod and web/package.json and this script is a pass-through.
set -euo pipefail
component="$1" base="$2"

case "$component" in
  api) marker="server/go.mod" ;;
  web) marker="web/package.json" ;;
  *) echo "effective-base: unknown component $component" >&2; exit 2 ;;
esac

if git cat-file -e "${base}:${marker}" 2>/dev/null; then
  echo "$base"; exit 0
fi

old_marker="api/go.mod" # rename-guard: allow
case "$component" in
  api) c="$(git log --format=%H -1 --fixed-strings --grep='chore(rename): move api/ to server/' HEAD)" # rename-guard: allow
       [[ -n "$c" && -n "$(git ls-tree --full-tree --name-only "$base" "$old_marker" 2>/dev/null)" ]] \
         || c="$(git log --format=%H -1 --fixed-strings --grep='chore(monorepo): move the Go API into api/' HEAD)" ;;
  web) m="$(git log --format=%H -1 --merges --fixed-strings --grep='chore(monorepo): import openctemio/ui' HEAD)"
       c="${m:+$(git rev-parse "${m}^2")}" ;;
esac
if [[ -z "${c:-}" ]]; then
  echo "effective-base: ${base} has no ${marker} and no monorepo cutover commit is in HEAD's history" >&2
  exit 2
fi
echo "effective-base: ${base} predates the monorepo; using ${c} for ${component}" >&2
echo "$c"
