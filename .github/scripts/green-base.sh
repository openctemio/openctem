#!/usr/bin/env bash
# green-base.sh: the newest commit of a pull request (before its head) whose
# required checks all passed. Prints its SHA, or nothing when there is none or
# the API cannot answer. Used by changed.sh for incremental pull request CI.
#
# A commit is green when, for every name in INCREMENTAL_CHECKS, at least one
# GitHub Actions check run of that name exists on the commit and every latest
# run of that name completed as success, skipped or neutral (a job skipped by
# `if:` reports skipped, and the OK aggregators are what is required).
# `security-gate` is not in the default list: it waits for a person's label and
# says nothing about what the code does.
#
# Only runs of the github-actions app count, so a status posted by another
# integration cannot vouch for a commit. Every failure path prints nothing,
# which makes the caller measure against the base (the full set of checks).
#
# Env: REPO or GITHUB_REPOSITORY, PR_NUMBER, PR_HEAD_SHA, GH_TOKEN (checks: read,
# pull-requests: read); INCREMENTAL_CHECKS (comma separated); GREEN_BASE_MAX
# (how many commits back to look, default 20).
set -uo pipefail

repo="${REPO:-${GITHUB_REPOSITORY:-}}"
pr="${PR_NUMBER:-}" head="${PR_HEAD_SHA:-}"
if [[ -z "$repo" || -z "$pr" || -z "$head" ]]; then echo "green-base: missing input" >&2; exit 0; fi
required="${INCREMENTAL_CHECKS:-API CI OK,Web CI OK,CodeQL OK,E2E OK,All-in-one OK,Secret Scanning,Workflow Lint}"
max="${GREEN_BASE_MAX:-20}"

commits="$(gh api --paginate "repos/${repo}/pulls/${pr}/commits?per_page=100" --jq '.[].sha' 2>/dev/null)" || {
  echo "green-base: cannot list the pull request's commits" >&2; exit 0; }

n=0
while IFS= read -r sha; do
  [[ -n "$sha" && "$sha" != "$head" ]] || continue
  n=$((n + 1)); [[ $n -le $max ]] || break
  runs="$(gh api --paginate "repos/${repo}/commits/${sha}/check-runs?filter=latest&per_page=100" \
    --jq '.check_runs[] | {name, status, conclusion, app: (.app.slug // "")}' 2>/dev/null | jq -s '.' 2>/dev/null)" || continue
  if jq -e --arg req "$required" '
      . as $runs
      | ($req | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $names
      | all($names[]; . as $n
          | [ $runs[] | select(.name == $n and .app == "github-actions") ] as $r
          | ($r | length) > 0
            and all($r[]; .status == "completed" and (.conclusion | IN("success", "skipped", "neutral"))))
    ' <<<"$runs" >/dev/null 2>&1; then
    echo "$sha"
    exit 0
  fi
  echo "green-base: ${sha:0:12} is not green" >&2
done < <(printf '%s\n' "$commits" | tac)
echo "green-base: no green commit among the last $max" >&2
exit 0
