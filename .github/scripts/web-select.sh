#!/usr/bin/env bash
# The Vitest files a pull request can affect. Run from web/ after `npm ci`.
#
#   web-select.sh <base-ref>
#
# Prints `ALL` (one line) when the change cannot be narrowed, otherwise the
# test files to run, one path (relative to web/) per line, possibly none.
# Anything unexpected prints ALL: the selection only removes work that cannot
# change the result.
#
# Narrowed only when every changed file is
#   - documentation (Markdown), web/e2e/ or web/docs/ (Vitest never runs them),
#   - the Go API (api/): its effect on the web is the generated contract, which
#     the workflow's `contract` job decides separately (a changed contract runs
#     everything), or
#   - source under web/src/ or web/console/src/, except web/src/test/ (the
#     setup every test shares).
# Anything else (package.json, the lockfile, a config, web/scripts/, public/,
# .github/, deploy/) runs everything.
#
# Narrowed set = the tests Vitest relates to the changed files through its
# module graph (`vitest list --changed`), plus every "gate" test: a test that
# reads source files from disk (fs, glob) to enforce a rule over the codebase.
# Those are not related through imports, so they run on every web change.
set -euo pipefail

base="${1:?usage: web-select.sh <base-ref>}"
prefix="$(git rev-parse --show-prefix)"; prefix="${prefix%/}"   # "web"
changed="$(git diff --name-only "$base" HEAD)" || { echo ALL; exit 0; }

while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *.md | "$prefix"/e2e/* | "$prefix"/docs/* | api/* | .claude/* | "$prefix"/.claude/*) ;;
    "$prefix"/src/test/*) echo ALL; exit 0 ;;
    "$prefix"/src/* | "$prefix"/console/src/*) ;;
    *) echo ALL; exit 0 ;;
  esac
done <<<"$changed"

[ -z "${WEB_SELECT_NO_LIST:-}" ] || { echo "narrow"; exit 0; }   # classification only (the test)

related="$(npx vitest list --filesOnly --changed "$base" 2>/dev/null)" || { echo ALL; exit 0; }
gates="$(grep -rlE 'readFileSync|readdirSync|existsSync|readFile\(|globSync|import\.meta\.glob|fast-glob' src console --include='*.test.ts' --include='*.test.tsx' 2>/dev/null || true)"
printf '%s\n%s\n' "$related" "$gates" | grep -E '\.test\.tsx?$' | LC_ALL=C sort -u || true
