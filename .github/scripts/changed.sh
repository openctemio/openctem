#!/usr/bin/env bash
# changed.sh
#
# Which areas did this event touch? Writes to $GITHUB_OUTPUT:
#   api=true|false   the Go API (api/) or a shared file
#   web=true|false   the web app (web/) or a shared file. An API change that
#                    changes the generated contract (spec, route manifest,
#                    route permission map) also runs the web checks: Web CI's
#                    contract job generates base and head and decides.
# The ONE place the routing rules live: every workflow's `changes` job calls
# this and reads the output it needs, so the rules cannot drift apart.
#
# Shared files run both sides: the root Makefile, go.work, anything under
# .github/ (workflows, these scripts, Dependabot, CODEOWNERS) and deploy/ (the
# all-in-one image, which embeds both components).
#
# Why the required-check workflows do not use `on.<event>.paths`: a workflow
# skipped by a paths filter leaves its required checks "Pending" forever and
# blocks the merge. A JOB skipped by `if:` reports Success. So those workflows
# always start, and this decides which jobs run. Workflows with no required
# check (api-security.yml, web-security.yml) use `paths:` directly and do not
# start at all for the other side.
#
# PR: diff against the base branch. Push: before..HEAD. Merge queue
# (merge_group): merge_group.base_sha..head_sha, i.e. only the queued PR.
# Anything else (schedule, dispatch, tag, first push of a branch, missing
# SHAs) runs everything: when in doubt, run.
set -euo pipefail

shared=(Makefile go.work go.work.sum .github/ deploy/)
api_paths=(api/ "${shared[@]}")
web_paths=(web/ "${shared[@]}")

out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/stdout}"; echo "$1=$2${3:+ ($3)}"; }
all() { out api true "$1"; out web true "$1"; exit 0; }

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    git fetch --no-tags --quiet origin "${GITHUB_BASE_REF}"
    range="origin/${GITHUB_BASE_REF}...HEAD" ;;
  push)
    before="${EVENT_BEFORE:-}"
    if [[ -z "$before" || "$before" =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2>/dev/null; then
      all "push without a usable 'before'"
    fi
    range="${before}..HEAD" ;;
  merge_group)
    # A queued group: base_sha is what the group sits on (the branch tip, or
    # the group ahead of it in the queue), head_sha is base + this PR. The
    # diff is exactly what this PR adds, so a queued web-only PR runs only
    # web jobs, as it did on the PR itself.
    base="${MG_BASE:-}" head="${MG_HEAD:-}"
    if [[ -z "$base" || -z "$head" ]]; then all "merge_group without base_sha/head_sha"; fi
    git cat-file -e "${base}^{commit}" 2>/dev/null || git fetch --no-tags --quiet origin "$base" || true
    if ! git cat-file -e "${base}^{commit}" 2>/dev/null || ! git cat-file -e "${head}^{commit}" 2>/dev/null; then
      all "merge_group commits not available"
    fi
    range="${base}..${head}" ;;
  *)
    all "event ${GITHUB_EVENT_NAME:-unknown} runs everything" ;;
esac

files="$(git diff --name-only "$range")"

# matches <prefix>... : first changed file under any prefix, or nothing.
matches() {
  local f p
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    for p in "$@"; do
      if [[ "$f" == "$p"* ]]; then echo "$f"; return 0; fi
    done
  done <<<"$files"
  return 1
}

echo "changed files in $range (first 50):"; awk 'NR <= 50 { print "  " $0 }' <<<"$files"
if hit="$(matches "${api_paths[@]}")"; then out api true "$hit"; else out api false "nothing under ${api_paths[*]}"; fi
if hit="$(matches "${web_paths[@]}")"; then out web true "$hit"; else out web false "nothing under ${web_paths[*]}"; fi
