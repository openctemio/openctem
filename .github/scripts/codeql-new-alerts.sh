#!/usr/bin/env bash
# Fails when a pull request introduces open code-scanning alerts of severity
# medium, high or critical (security_severity_level) that the base branch does
# not already have. Called by the `CodeQL OK` job in codeql.yml on pull_request.
#
# Threat model: CodeQL itself never fails a run on findings, so without this a
# PR can add an injection or XSS alert and still merge. The gate is implemented
# here (not as a repository ruleset `code_scanning` rule) because the workflow
# analyses only the changed side on pull_request and nothing on merge_group, and
# a ruleset rule waits forever for a tool that did not run.
#
# "New" = an alert number present on refs/pull/<n>/merge and absent from the
# base branch. Code scanning matches alerts across refs by fingerprint, so an
# alert that already exists on the base keeps its number and is not counted,
# even when the PR shifts its line. Alerts of a side the PR did not analyse are
# the base's own alerts and are therefore never new.
#
# Inputs (env): GH_TOKEN (security-events: read), REPO (owner/name), PR_NUMBER,
# BASE_REF (branch name). Optional: GITHUB_STEP_SUMMARY.
set -euo pipefail

: "${REPO:?}" "${PR_NUMBER:?}" "${BASE_REF:?}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
sev='map(select((.rule.security_severity_level // "") | IN("medium","high","critical")))'

fetch() { # fetch <ref> -> JSON array of open alerts at medium or above
  gh api --paginate "repos/${REPO}/code-scanning/alerts?ref=${1}&state=open&per_page=100" \
    | jq -s "add // [] | ${sev} | map({number, html_url, rule: {id: .rule.id, security_severity_level: .rule.security_severity_level}, most_recent_instance: {location: .most_recent_instance.location}})"
}

# The alert lists can be thousands long (a release pull request against a far-behind
# branch), more than a command line can carry, so they go through files.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fetch "refs/pull/${PR_NUMBER}/merge" >"$work/pr.json"
fetch "refs/heads/${BASE_REF}" >"$work/base.json"

new="$(jq -n --slurpfile pr "$work/pr.json" --slurpfile base "$work/base.json" \
  '($base[0] | map(.number)) as $b | $pr[0] | map(select(.number as $n | $b | index($n) | not))')"
count="$(jq 'length' <<<"$new")"

if [[ "$count" -eq 0 ]]; then
  echo "No new code-scanning alerts of severity medium or higher." | tee -a "$summary"
  exit 0
fi

{
  echo "### New code-scanning alerts (medium or higher): ${count}"
  echo
  echo "| Severity | Rule | Location | Alert |"
  echo "|---|---|---|---|"
  jq -r '.[] | "| \(.rule.security_severity_level) | \(.rule.id) | `\(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)` | [#\(.number)](\(.html_url)) |"' <<<"$new"
} | tee -a "$summary"
jq -r '.[] | "::error file=\(.most_recent_instance.location.path),line=\(.most_recent_instance.location.start_line)::\(.rule.security_severity_level) \(.rule.id): this PR introduces a new code-scanning alert"' <<<"$new"
exit 1
