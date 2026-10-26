#!/usr/bin/env bash
# changed.sh
#
# Which areas did this event touch? Writes to $GITHUB_OUTPUT:
#   api=true|false   the Go API (api/) or a shared file
#   web=true|false   the web app (web/) or a shared file. An API change that
#                    changes the generated contract (spec, route manifest,
#                    route permission map) also runs the web checks: Web CI's
#                    contract job generates base and head and decides.
#   docs=true|false  a documentation file changed (informational).
#   migrations=true|false  a database migration or the database role script
#                    changed (api/migrations/, api/deploy/postgres/): the
#                    least-privilege and PostgreSQL 18 jobs then also run on
#                    a pull request.
#   full=true|false  run the full tier (what the merge queue runs). Always
#                    true except on pull_request, where it is true when the PR
#                    has the `ci:full` label or changes a CI definition
#                    (.github/workflows/, .github/scripts/, .github/actions/).
#                    The labels are read live through the API (GH_TOKEN,
#                    PR_NUMBER), so adding the label and re-running the jobs
#                    is enough; PR_LABELS (the event's label names as a JSON
#                    array) is the fallback.
#
#   range=<git range>  the range api/web/docs/migrations were computed from.
#   incremental=true|false, since=<sha>  (pull request only) the answers above are
#                    measured against the PR's last commit whose required checks
#                    all passed (green-base.sh), so a push re-runs only what it
#                    touched. See the incremental rules below.
#   release=true|false  the PR is a verified release (release-provenance.sh).
#
# Incremental rules (pull_request, action synchronize only): never when the PR
# changes anything under .github/ (a CI change re-runs everything; an earlier
# check cannot vouch for a changed CI), never without a green commit, never when
# the API cannot be asked (no token). `full` is always decided against the base,
# so a PR that changed a CI definition keeps the full tier for what runs. A
# merge of the base into the branch is just a commit: what it changed since the
# green commit is what runs. Release PRs (head release/vX.Y.Z into main) whose
# content release-provenance.sh verifies skip the heavy suites. merge_group and
# pushes never use any of this: they run the full tier of what they changed.
#
# Documentation never counts as code for api/web: Markdown anywhere, all of
# api/docs/, and the agent notes under .claude/. A docs-only PR therefore runs
# none of the Go or web suites (Docs check, the changelog check in API CI's
# `changes` job and the secret scan still run). Exception: Markdown that a
# test generates and compares (api/docs/configuration/environment-variables.md,
# TestEnvDocsUpToDate) counts as API code.
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
all() { out api true "$1"; out web true "$1"; out docs true "$1"; out migrations true "$1"; out full true "$1"; out release false; out incremental false; exit 0; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
incremental=false since="" head_sha="" action=""
case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    git fetch --no-tags --quiet origin "${GITHUB_BASE_REF}"
    range="origin/${GITHUB_BASE_REF}...HEAD"
    ev="${GITHUB_EVENT_PATH:-}"
    ev_get() { if [[ -n "$ev" && -f "$ev" ]]; then jq -r "$1 // empty" "$ev" 2>/dev/null || true; fi; }
    action="${EVENT_ACTION:-$(ev_get .action)}"
    head_sha="${PR_HEAD_SHA:-$(ev_get .pull_request.head.sha)}"
    PR_NUMBER="${PR_NUMBER:-$(ev_get .number)}" ;;
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

# A release PR whose content is already verified on develop skips the heavy suites.
if [[ "${GITHUB_EVENT_NAME}" == pull_request ]] \
  && reason="$(HEAD_SHA="$head_sha" bash "$HERE/release-provenance.sh")"; then
  out api false "release provenance: $reason"; out web false "release provenance"
  out docs false "release provenance"; out migrations false "release provenance"
  out full false "release provenance"; out release true "$reason"
  out incremental false; out since ""; out range "$range"
  exit 0
fi
out release false

all_files="$(git diff --name-only "$range")"

# is_docs <path>: documentation only, see the header.
is_docs() {
  case "$1" in
    api/docs/configuration/environment-variables.md) return 1 ;;
    *.md | api/docs/* | .claude/* | */.claude/*) return 0 ;;
  esac
  return 1
}
files="" docs=""
classify() { # classify <name list>: sets files and docs
  local f
  files="" docs=""
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    if is_docs "$f"; then docs="$f"; else files+="$f"$'\n'; fi
  done <<<"$1"
}
classify "$all_files"

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

# The full tier is decided against the BASE, whatever the answers below measure.
full_out="" full_why=""
if [[ "${GITHUB_EVENT_NAME}" != pull_request ]]; then
  full_out=true full_why="${GITHUB_EVENT_NAME}"
elif hit="$(matches .github/workflows/ .github/scripts/ .github/actions/)"; then
  full_out=true full_why="CI definition changed: $hit"
else
  labels="$(jq -r '.[]?' <<<"${PR_LABELS:-[]}" 2>/dev/null || true)"
  if [[ -n "${PR_NUMBER:-}" && -n "${GH_TOKEN:-}" ]] && command -v gh >/dev/null 2>&1; then
    if live="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/labels" --jq '.[].name' 2>/dev/null)"; then labels="$live"; fi
  fi
  if grep -qxF 'ci:full' <<<"$labels"; then full_out=true full_why="label ci:full"; else full_out=false full_why="pull request without ci:full"; fi
fi

# Incremental: measure against the PR's last green commit. Anything under
# .github/ in the PR (any CI file, also Dependabot and CODEOWNERS) opts out.
if [[ "${GITHUB_EVENT_NAME}" == pull_request && "$action" == synchronize && -n "$head_sha" \
  && -n "${PR_NUMBER:-}" && -n "${GH_TOKEN:-}" ]] \
  && ! grep -q '^\.github/' <<<"$all_files"; then
  if since="$(PR_HEAD_SHA="$head_sha" PR_NUMBER="$PR_NUMBER" bash "$HERE/green-base.sh")" && [[ -n "$since" ]] \
    && git cat-file -e "${since}^{commit}" 2>/dev/null && git cat-file -e "${head_sha}^{commit}" 2>/dev/null \
    && inc_files="$(git diff --name-only "${since}..${head_sha}")"; then
    incremental=true
    range="${since}..${head_sha}"
    all_files="$inc_files"
    classify "$all_files"
    echo "::notice title=Incremental CI::unchanged since ${since:0:12} (last commit of this PR with every required check green); only the changes after it are checked"
    {
      echo "### Incremental CI"; echo
      echo "Measured against \`${since:0:12}\`, the last commit of this PR whose required checks all passed. Areas with no change since report success as *unchanged since ${since:0:12}*. The merge queue runs the full tier."
    } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  else
    since=""
    echo "incremental: no green commit to compare with; measuring against the base"
  fi
fi

echo "changed files in $range (first 50):"; awk 'NR <= 50 { print "  " $0 }' <<<"$all_files"
unch() { if [[ "$incremental" == true ]]; then echo "unchanged since ${since:0:12}"; else echo "$1"; fi; }
if [[ -n "$docs" ]]; then out docs true "$docs"; else out docs false "$(unch 'no documentation file')"; fi
if hit="$(matches "${api_paths[@]}")"; then out api true "$hit"; else out api false "$(unch "nothing under ${api_paths[*]}")"; fi
if hit="$(matches "${web_paths[@]}")"; then out web true "$hit"; else out web false "$(unch "nothing under ${web_paths[*]}")"; fi
if hit="$(matches api/migrations/ api/deploy/postgres/)"; then out migrations true "$hit"; else out migrations false "$(unch 'no migration or role script')"; fi
out full "$full_out" "$full_why"
out incremental "$incremental" "${since:+since ${since:0:12}}"
out since "$since"
if [[ "${GITHUB_EVENT_NAME}" == pull_request ]]; then out range "$range"; fi
