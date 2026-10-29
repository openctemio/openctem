#!/usr/bin/env bash
# Fails when a workflow job has no `timeout-minutes`. Without one a hung job
# holds a runner for GitHub's default of 360 minutes; in the merge queue it also
# holds the group. Jobs that call a reusable workflow (`uses:`) cannot set one
# (the called workflow's jobs do).
#
# Usage: check-job-timeouts.sh [workflow files...]  (default .github/workflows/*.yml)
# Reads the repository's layout: `jobs:` at column 0, job ids indented by two
# spaces, job keys by four.
set -euo pipefail
[ $# -gt 0 ] || set -- .github/workflows/*.yml .github/workflows/*.yaml
bad=0
for f in "$@"; do
  [ -f "$f" ] || continue
  out="$(awk '
    function flush() { if (job != "" && !ok) print FILENAME ": job \"" job "\" has no timeout-minutes"; job = ""; ok = 0 }
    /^jobs:[[:space:]]*$/ { injobs = 1; next }
    /^[^[:space:]#]/ { flush(); injobs = 0; next }
    !injobs { next }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); job = $1; sub(/:$/, "", job); next }
    /^    (timeout-minutes|uses):/ { ok = 1 }
    END { flush() }
  ' "$f")"
  if [ -n "$out" ]; then echo "$out"; bad=1; fi
done
if [ "$bad" -ne 0 ]; then
  echo "::error::give every job a timeout-minutes (about 2-3x its p90 duration)"
  exit 1
fi
echo "Every job has a timeout-minutes."
