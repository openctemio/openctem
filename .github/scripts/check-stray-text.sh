#!/usr/bin/env bash
# Fails when a tracked file holds stray markup lines or an absolute local path.
# Prints file:line only.
#
# Legitimate uses are listed in .github/stray-text-allow.txt, one per line:
#   <path>|<fixed substring that must be on the matching line>
# Lines starting with # and blank lines are ignored.
#
# Run from the repository root: bash .github/scripts/check-stray-text.sh
set -euo pipefail

allow_file="${STRAY_TEXT_ALLOW:-.github/stray-text-allow.txt}"
re='<invoke|</invoke>|<parameter name=|</content>|/home/[a-z][a-z0-9_-]*/|/Users/[A-Za-z][A-Za-z0-9_.-]*/|(^|[[:space:]])cd +/tmp/'

allowed() { # path line
  [[ -f "$allow_file" ]] || return 1
  local p s
  while IFS='|' read -r p s; do
    [[ -z "$p" || "$p" == \#* || -z "${s:-}" ]] && continue
    [[ "$p" == "$1" && "$2" == *"$s"* ]] && return 0
  done < "$allow_file"
  return 1
}

found=0
while IFS= read -r hit; do
  [[ -z "$hit" ]] && continue
  rest="${hit#*:}"; path="${hit%%:*}"; line="${rest%%:*}"; text="${rest#*:}"
  allowed "$path" "$text" && continue
  found=$((found + 1))
  [[ "$found" -eq 1 ]] && echo "::error::Pasted session text or an internal path found in a tracked file (remove it, or list a legitimate line in $allow_file):"
  echo "  $path:$line"
done < <(git -c core.quotepath=off grep -I -n -E "$re" -- . \
  ':(exclude).github/scripts/check-stray-text*' ':(exclude).github/stray-text-allow.txt' || true)
exit $(( found > 0 ))
