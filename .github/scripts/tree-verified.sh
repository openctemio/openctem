#!/usr/bin/env bash
# tree-verified.sh: has the exact code under test already passed every
# required check?
#
# Two jobs, one script (every workflow's `changes` job runs it):
#
#  1. RECORD (every event). Prints one annotation, `openctem-tested-tree <tree>`,
#     naming the git tree of the commit this run checked out. For a pull request
#     that commit is GitHub's merge of the PR into its base (refs/pull/N/merge),
#     which GitHub does not otherwise expose per run. The annotation is attached
#     to the job's check run and read back by step 2.
#
#  2. DECIDE (merge_group, and push when TREE_EVENTS says so). Prints
#     `verified=true|false`. True when a candidate commit
#       - has a tree equal to the tree of the commit under test, and
#       - every check in TREE_CHECKS has a github-actions check run on it, every
#         latest run of that name completed as success, skipped or neutral, and
#       - every `openctem-tested-tree` record on its github-actions check runs
#         names that same tree (at least one record exists).
#     Identical tree means identical code, so the checks passed for the same
#     bytes. Any difference, error or missing input prints false and the normal
#     tier runs: the check fails toward running the tests.
#
# Area mode (TREE_AREA and TREE_PATHS set; used by API CI, Web CI and Web E2E).
# The tree of the whole repository rarely repeats, because the merge queue keeps
# adding other pull requests. What a workflow tests is only the part it watches
# (for API CI: api/ and the shared files). In area mode the "tree" is the list
# of the git object ids of TREE_PATHS (the area id), and the record is
# `openctem-tested-area <TREE_AREA> <area id>`. A candidate then also covers a
# commit of the queue ahead of us or of develop that differs elsewhere (a
# web-only change next to an API run). Only the workflow's own check
# (TREE_CHECKS, e.g. "API CI OK") must have passed on the candidate. Records
# are written only by a run of the full tier (TREE_FULL=true, the default): a
# fast-tier pull request run proves less than the queue and must never be reused.
#
# Candidates (cheap first):
#   - the head commit of the pull request named by the merge-queue branch
#     (gh-readonly-queue/<base>/pr-<N>-<sha>): its checks ran on the merge ref
#     whose tree the record names;
#   - the last TREE_WINDOW first-parent commits of develop, main and the queue's
#     base whose own tree equals ours (earlier merge-queue or push runs);
#   - area mode only: the last TREE_WINDOW first-parent commits from
#     MG_BASE (merge_group.base_sha: the queue entry just ahead of us, or
#     develop's head) whose area id equals ours.
#
# Trust: only check runs of the github-actions app count (a status or check run
# posted by any other integration is ignored), annotations are read only from
# those runs, and a fork pull request never reaches the queue. See
# api/docs/development/ci-cd.md ("Reusing a verified tree").
#
# Env: EVENT (github.event_name), SHA (github.sha), HEAD_REF (merge_group.head_ref),
#   REPO, GH_TOKEN (checks: read, pull-requests: read), TREE_EVENTS (default
#   "merge_group push"), TREE_CHECKS (comma separated), TREE_WINDOW (default 30),
#   MG_BASE, TREE_AREA, TREE_PATHS (space separated), TREE_FULL (default true).
#   Outputs (GITHUB_OUTPUT when set): verified, note.
set -uo pipefail

req_default="API CI OK,Web CI OK,CodeQL OK,E2E OK,All-in-one OK,Secret Scanning,Workflow Lint"
required="${TREE_CHECKS:-$req_default}"
events="${TREE_EVENTS:-merge_group push}"
window="${TREE_WINDOW:-30}"
event="${EVENT:-}" sha="${SHA:-}" repo="${REPO:-${GITHUB_REPOSITORY:-}}"
area="${TREE_AREA:-}" paths="${TREE_PATHS:-}" full="${TREE_FULL:-true}" mgbase="${MG_BASE:-}"
[ -n "$area" ] && [ -n "$paths" ] || { area="" paths=""; }

out() { # <true|false> [note] [stderr reason]
  echo "verified=$1"
  echo "note=${2:-}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then { echo "verified=$1"; echo "note=${2:-}"; } >>"$GITHUB_OUTPUT"; fi
  if [ -n "${3:-}" ]; then echo "tree-verified: $3" >&2; fi
  exit 0
}

case "$sha" in '' | *[!0-9a-f]*) out false "" "missing or bad sha" ;; esac
tree="$(git rev-parse --verify --quiet "${sha}^{tree}")" || out false "" "cannot read the tree of $sha"

# area_id <commit>: identifies the content of TREE_PATHS in <commit>. Empty
# when a path cannot be read at all (the caller treats that as "no match").
area_id() {
  local c=$1 p o lines=""
  for p in $paths; do
    o="$(git rev-parse --verify --quiet "${c}:${p}" 2>/dev/null)" || o=none
    lines+="${p}=${o}"$'\n'
  done
  printf '%s' "$lines" | git hash-object --stdin 2>/dev/null
}
myarea=""
if [ -n "$area" ]; then myarea="$(area_id "$sha")" || myarea=""; [ -n "$myarea" ] || area=""; fi

# Record. A workflow command: it becomes an annotation on this job's check run.
# Only the full tier records (see Area mode above).
if [ "$full" = true ]; then
  echo "::notice title=tested-tree::openctem-tested-tree ${tree}"
  if [ -n "$area" ]; then echo "::notice title=tested-area::openctem-tested-area ${area} ${myarea}"; fi
fi

case " $events " in *" $event "*) ;; *) out false ;; esac
[ -n "$repo" ] || out false "" "missing repo"
case "$window" in '' | *[!0-9]*) window=30 ;; esac

# runs <commit>: the commit's latest github-actions check runs as compact JSON
# lines {id,name,status,conclusion,url,ann}.
runs() {
  gh api --paginate "repos/${repo}/commits/${1}/check-runs?filter=latest&per_page=100" \
    --jq '.check_runs[] | select((.app.slug // "") == "github-actions")
          | {id, name, status, conclusion, url: .html_url, ann: (.output.annotations_count // 0)}' 2>/dev/null
}

# check <commit>: 0 and prints "<url>" when the commit passed the contract.
check() {
  local c=$1 rj
  rj="$(runs "$c" | jq -s '.' 2>/dev/null)" || return 1
  [ -n "$rj" ] || return 1
  jq -e --arg req "$required" '
      . as $runs
      | ($req | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $names
      | all($names[]; . as $n
          | [ $runs[] | select(.name == $n) ] as $r
          | ($r | length) > 0
            and all($r[]; .status == "completed" and (.conclusion | IN("success", "skipped", "neutral"))))
    ' <<<"$rj" >/dev/null 2>&1 || return 1
  # Every record on this commit's runs must name our tree; at least one must exist.
  local id seen=0 msg
  while IFS= read -r id; do
    [[ "$id" =~ ^[0-9]+$ ]] || continue
    while IFS= read -r msg; do
      case "$msg" in
        "openctem-tested-tree "*)
          if [ -z "$area" ]; then
            seen=$((seen + 1))
            [ "${msg#openctem-tested-tree }" = "$tree" ] || return 1
          fi ;;
        "openctem-tested-area ${area} "*)
          if [ -n "$area" ]; then
            seen=$((seen + 1))
            [ "${msg#openctem-tested-area "${area}" }" = "$myarea" ] || return 1
          fi ;;
      esac
    done < <(gh api "repos/${repo}/check-runs/${id}/annotations?per_page=100" --jq '.[].message' 2>/dev/null)
  done < <(jq -r '.[] | select(.ann > 0) | .id' <<<"$rj")
  [ "$seen" -gt 0 ] || return 1
  jq -r '[.[] | select(.name == "API CI OK")][0].url // ""' <<<"$rj"
}

report() { # <commit> <url>
  if [ -n "$area" ]; then
    out true "${area} area ${myarea} (${paths}) already verified at ${1} (${2:-https://github.com/${repo}/commit/${1}/checks})"
  fi
  out true "tree ${tree} already verified at ${1} (${2:-https://github.com/${repo}/commit/${1}/checks})"
}

base=""
cands=()
if [ "$event" = merge_group ]; then
  ref="${HEAD_REF#refs/heads/}"
  if [[ "$ref" =~ ^gh-readonly-queue/([A-Za-z0-9._/-]+)/pr-([0-9]+)-[0-9a-f]{7,40}$ ]]; then
    base="${BASH_REMATCH[1]}"
    pr="${BASH_REMATCH[2]}"
    head="$(gh api "repos/${repo}/pulls/${pr}" --jq '.head.sha' 2>/dev/null)" || head=""
    [[ "$head" =~ ^[0-9a-f]{40}$ ]] && cands+=("$head")
  fi
fi
heads=(develop main)
[ -n "$base" ] && heads+=("$base")
# Area mode: the queue entry ahead of us (and develop under it) by area id.
if [ -n "$area" ] && [[ "$mgbase" =~ ^[0-9a-f]{40}$ ]] && git cat-file -e "${mgbase}^{commit}" 2>/dev/null; then
  while IFS= read -r c; do
    [ "$c" = "$sha" ] && continue
    [ "$(area_id "$c")" = "$myarea" ] && cands+=("$c")
  done < <(git rev-list --first-parent -n "$window" "$mgbase" 2>/dev/null)
fi
for b in "${heads[@]}"; do
  git rev-parse --verify --quiet "refs/remotes/origin/${b}" >/dev/null 2>&1 || continue
  while IFS= read -r c; do
    [ "$c" = "$sha" ] && continue
    if [ -n "$area" ]; then
      [ "$(area_id "$c")" = "$myarea" ] && cands+=("$c")
    else
      [ "$(git rev-parse --verify --quiet "${c}^{tree}")" = "$tree" ] && cands+=("$c")
    fi
  done < <(git rev-list --first-parent -n "$window" "refs/remotes/origin/${b}" 2>/dev/null)
done

seen_c=" "
for c in "${cands[@]+"${cands[@]}"}"; do
  case "$seen_c" in *" $c "*) continue ;; esac
  seen_c+="$c "
  if url="$(check "$c")"; then report "$c" "$url"; fi
done
if [ -n "$area" ]; then out false "" "no verified commit with ${area} area ${myarea}"; fi
out false "" "no verified commit with tree $tree"
