#!/usr/bin/env bash
# changelog.sh: a Markdown changelog preview, grouped by conventional type,
# for the release train issue and the run summary (api/docs/rfcs/RFC-037).
#
#   changelog.sh [--repo DIR] [--title vX.Y.Z] [--since vA.B.C] [--max N] -- <git log revision args>
#
# The GitHub Release itself uses GitHub's generated notes (release.yml); this
# is the preview a person reads before pressing Run. Subjects are passed
# through sanitize-notes.py: @mentions are escaped and emails dropped, so an
# issue body never pings a stranger.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="."
TITLE=""
SINCE=""
MAX=40
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift ;;
    --title) TITLE="$2"; shift ;;
    --since) SINCE="$2"; shift ;;
    --max) MAX="$2"; shift ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ $# -gt 0 ]] || { echo "usage: $0 [options] -- <revision args>" >&2; exit 2; }

lines="$(mktemp)"
trap 'rm -f "$lines"' EXIT

# One line per commit: <group>\t<short sha>\t<subject>. Groups, in print order:
# 1 breaking, 2 security, 3 feat, 4 fix, 5 perf, 6 other.
git -C "$REPO" log --no-merges --format='%h%x1f%s%x1f%b%x1e' "$@" |
  awk -v RS='\036' -F '\037' '
    {
      sub(/^\n+/, "")
      if ($0 == "") next
      sha = $1; subj = $2; body = $3
      g = 6
      if (subj ~ /^[A-Za-z]+(\([^)]*\))?!:/ || body ~ /(^|\n)BREAKING[ -]CHANGE:/) g = 1
      else if (subj ~ /^[A-Za-z]+\(security\):/ || subj ~ /^security(\([^)]*\))?:/) g = 2
      else if (subj ~ /^feat(\([^)]*\))?:/) g = 3
      else if (subj ~ /^fix(\([^)]*\))?:/) g = 4
      else if (subj ~ /^perf(\([^)]*\))?:/) g = 5
      printf "%d\t%s\t%s\n", g, sha, subj
    }' >"$lines"

total="$(wc -l <"$lines" | tr -d ' ')"
{
  if [[ -n "$TITLE" ]]; then
    echo "## $TITLE"
    echo
  fi
  if [[ -n "$SINCE" ]]; then
    echo "$total commit(s) since $SINCE."
  else
    echo "$total commit(s)."
  fi
  names=("" "Breaking changes" "Security" "Features" "Fixes" "Performance" "Other")
  for g in 1 2 3 4 5 6; do
    n="$(awk -F '\t' -v g="$g" '$1 == g' "$lines" | wc -l | tr -d ' ')"
    [[ "$n" -gt 0 ]] || continue
    echo
    echo "### ${names[$g]} ($n)"
    echo
    awk -F '\t' -v g="$g" -v max="$MAX" '
      $1 == g { if (++c <= max) printf "- %s (%s)\n", $3, $2 }
      END { if (c > max) printf "- ... and %d more\n", c - max }
    ' "$lines"
  done
} | python3 "$HERE/sanitize-notes.py"
