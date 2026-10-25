#!/usr/bin/env bash
# Prints `verified=true` (to $GITHUB_OUTPUT when set) when this push to
# develop is a commit the merge queue already tested with THIS workflow and
# passed; `verified=false` otherwise.
#
# The merge queue tests the exact commit it then fast-forwards develop to, so
# the push run that follows would test the same tree again (2026-10-18..25:
# 360 of 365 develop pushes had a passing merge_group run of the same SHA).
# Workflows use this to skip their heavy jobs on such a push.
#
# Trust: only runs GitHub itself records count. A run must have
#   event == merge_group   (only the merge queue creates these; no pull
#                           request or token can start one)
#   path  == this workflow's file, head_sha == this push's SHA,
#   conclusion == success.
# A merge_group run executes the workflow file of the commit it tests, which
# is this commit, so it ran the same jobs this push would run. Anything else
# (another event, ref, error, API failure, missing input) prints false and the
# workflow runs in full: the check fails toward running the tests.
#
# Env: EVENT (github.event_name), REF (github.ref), SHA (github.sha),
#      WORKFLOW_REF (github.workflow_ref, "<owner>/<repo>/<path>@<ref>"),
#      REPO (github.repository), GH_TOKEN (needs actions: read).
set -uo pipefail

out() {
  echo "verified=$1"
  [ -n "${GITHUB_OUTPUT:-}" ] && echo "verified=$1" >>"$GITHUB_OUTPUT"
  [ -n "${2:-}" ] && echo "queue-verified: $2" >&2
  exit 0
}

[ "${EVENT:-}" = push ] || out false
[ "${REF:-}" = refs/heads/develop ] || out false
[ -n "${SHA:-}" ] && [ -n "${REPO:-}" ] && [ -n "${WORKFLOW_REF:-}" ] || out false "missing input"
case "$SHA" in *[!0-9a-f]*) out false "bad sha" ;; esac

path=${WORKFLOW_REF#"$REPO/"}
path=${path%@*}
case "$path" in .github/workflows/*.yml | .github/workflows/*.yaml) ;; *) out false "unexpected workflow path $path" ;; esac

n=$(gh api "repos/$REPO/actions/runs?event=merge_group&head_sha=$SHA&status=success&per_page=100" \
  --jq "[.workflow_runs[] | select(.event == \"merge_group\" and .head_sha == \"$SHA\" and .path == \"$path\" and .conclusion == \"success\")] | length" 2>/dev/null) ||
  out false "cannot list runs"
case "$n" in '' | *[!0-9]*) out false "unexpected answer" ;; esac
[ "$n" -gt 0 ] && out true "the merge queue passed $path on $SHA"
out false
