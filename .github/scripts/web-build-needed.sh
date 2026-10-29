#!/usr/bin/env bash
# Does a push to develop need `next build`? Prints `true` or `false` (and
# writes build=<it> to $GITHUB_OUTPUT). False only when every changed file is
# a test, a test helper, a Playwright spec or documentation: none of them is in
# the production bundle. Anything else, or anything unclear, is true.
#
# Env: EVENT (github.event_name), BEFORE (github.event.before).
set -uo pipefail
out() { echo "$1"; [ -z "${GITHUB_OUTPUT:-}" ] || echo "build=$1" >> "$GITHUB_OUTPUT"; exit 0; }
[ "${EVENT:-}" = push ] || out true
before="${BEFORE:-}"
if [[ -z "$before" || "$before" =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2>/dev/null; then out true; fi
files="$(git diff --name-only "$before" HEAD)" || out true
[ -n "$files" ] || out true
while IFS= read -r f; do
  case "$f" in
    *.md | web/e2e/* | web/docs/* | web/src/test/* | */__tests__/* | *.test.ts | *.test.tsx | *.spec.ts | *.spec.tsx) ;;
    *) out true ;;
  esac
done <<<"$files"
out false
