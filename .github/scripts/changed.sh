#!/usr/bin/env bash
# changed.sh <name> <path-prefix>...
#
# Prints "<name>=true|false" to $GITHUB_OUTPUT: did this event touch any of the
# given path prefixes? Used by the `changes` job of every component workflow.
#
# Why not `on.<event>.paths`: a workflow skipped by a paths filter leaves its
# required checks "Pending" forever and blocks the merge. A JOB skipped by `if:`
# reports Success. So every workflow always starts, and this decides which jobs
# run. See docs.github.com ... "Handling skipped but required checks".
#
# Why not dorny/paths-filter: one less third-party action with write-adjacent
# tokens; this is 30 lines of git.
#
# Anything that is not a PR or an ordinary branch push (schedule, dispatch, tag,
# first push of a branch, merge_group) runs everything: when in doubt, run.
set -euo pipefail
name="$1"; shift

emit() { echo "$name=$1" >> "${GITHUB_OUTPUT:-/dev/stdout}"; echo "$name=$1 ($2)"; }

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    git fetch --no-tags --quiet origin "${GITHUB_BASE_REF}"
    range="origin/${GITHUB_BASE_REF}...HEAD" ;;
  push)
    before="${EVENT_BEFORE:-}"
    if [[ -z "$before" || "$before" =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2>/dev/null; then
      emit true "push without a usable 'before'"; exit 0
    fi
    range="${before}..HEAD" ;;
  *)
    emit true "event ${GITHUB_EVENT_NAME:-unknown} runs everything"; exit 0 ;;
esac

while IFS= read -r f; do
  for prefix in "$@"; do
    if [[ -n "$f" && "$f" == "$prefix"* ]]; then
      emit true "$f matches $prefix in $range"; exit 0
    fi
  done
done <<<"$(git diff --name-only "$range")"
emit false "no file under: $* in $range"
