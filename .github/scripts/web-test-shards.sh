#!/usr/bin/env bash
# The Vitest shard list of Web CI's `tests` job. Writes `shards=<json array>` to
# $GITHUB_OUTPUT.
#
#   EVENT=pull_request FULL=false BASE_REF=develop web-test-shards.sh
#
# A pull request that web-select.sh can narrow runs a handful of test files, so
# one shard is enough (each shard costs a runner and an `npm ci`). Everything
# else (merge_group, push, schedule, the `ci:full` label, a change that cannot
# be narrowed) keeps the three balanced shards: the merge queue runs the full
# tier unchanged. Any doubt answers three shards. The workflow also widens the
# list to three when the API contract changed (known only after `contract`).
# Run from the repository root.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${GITHUB_OUTPUT:-/dev/stdout}"
all='[1,2,3]'
if [ "${EVENT:-}" = pull_request ] && [ "${FULL:-}" != true ] && [ -n "${BASE_REF:-}" ]; then
  git fetch --no-tags --quiet origin "$BASE_REF" 2>/dev/null || true
  if base="$(git merge-base "origin/$BASE_REF" HEAD 2>/dev/null)"; then
    sel="$(cd web && WEB_SELECT_NO_LIST=1 bash "$here/web-select.sh" "$base" 2>/dev/null)" || sel=ALL
    if [ "$sel" = narrow ]; then echo "shards=[1]" >> "$out"; exit 0; fi
  fi
fi
echo "shards=$all" >> "$out"
