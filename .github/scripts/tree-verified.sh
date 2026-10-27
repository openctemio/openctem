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
# Candidates (cheap first):
#   - the head commit of the pull request named by the merge-queue branch
#     (gh-readonly-queue/<base>/pr-<N>-<sha>): its checks ran on the merge ref
#     whose tree the record names;
#   - the last TREE_WINDOW first-parent commits of develop, main and the queue's
#     base whose own tree equals ours (earlier merge-queue or push runs).
#
# Trust: only check runs of the github-actions app count (a status or check run
# posted by any other integration is ignored), annotations are read only from
# those runs, and a fork pull request never reaches the queue. See
# api/docs/development/ci-cd.md ("Reusing a verified tree").
#
# Env: EVENT (github.event_name), SHA (github.sha), HEAD_REF (merge_group.head_ref),
#   REPO, GH_TOKEN (checks: read, pull-requests: read), TREE_EVENTS (default
#   "merge_group push"), TREE_CHECKS (comma separated), TREE_WINDOW (default 30).
#   Outputs (GITHUB_OUTPUT when set): verified, note.
set -uo pipefail

req_default="API CI OK,Web CI OK,CodeQL OK,E2E OK,All-in-one OK,Secret Scanning,Workflow Lint"
required="${TREE_CHECKS:-$req_default}"
events="${TREE_EVENTS:-merge_group push}"
window="${TREE_WINDOW:-30}"
event="${EVENT:-}" sha="${SHA:-}" repo="${REPO:-${GITHUB_REPOSITORY:-}}"

out() { # <true|false> [note] [stderr reason]
  echo "verified=$1"
  echo "note=${2:-}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then { echo "verified=$1"; echo "note=${2:-}"; } >>"$GITHUB_OUTPUT"; fi
  if [ -n "${3:-}" ]; then echo "tree-verified: $3" >&2; fi
  exit 0
}

case "$sha" in '' | *[!0-9a-f]*) out false "" "missing or bad sha" ;; esac
tree="$(git rev-parse --verify --quiet "${sha}^{tree}")" || out false "" "cannot read the tree of $sha"
# Record. A workflow command: it becomes an annotation on this job's check run.
echo "::notice title=tested-tree::openctem-tested-tree ${tree}"

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
          seen=$((seen + 1))
          [ "${msg#openctem-tested-tree }" = "$tree" ] || return 1 ;;
      esac
    done < <(gh api "repos/${repo}/check-runs/${id}/annotations?per_page=100" --jq '.[].message' 2>/dev/null)
  done < <(jq -r '.[] | select(.ann > 0) | .id' <<<"$rj")
  [ "$seen" -gt 0 ] || return 1
  jq -r '[.[] | select(.name == "API CI OK")][0].url // ""' <<<"$rj"
}

report() { # <commit> <url>
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
for b in "${heads[@]}"; do
  git rev-parse --verify --quiet "refs/remotes/origin/${b}" >/dev/null 2>&1 || continue
  while IFS= read -r c; do
    [ "$c" = "$sha" ] && continue
    [ "$(git rev-parse --verify --quiet "${c}^{tree}")" = "$tree" ] && cands+=("$c")
  done < <(git rev-list --first-parent -n "$window" "refs/remotes/origin/${b}" 2>/dev/null)
done

seen_c=" "
for c in "${cands[@]+"${cands[@]}"}"; do
  case "$seen_c" in *" $c "*) continue ;; esac
  seen_c+="$c "
  if url="$(check "$c")"; then report "$c" "$url"; fi
done
out false "" "no verified commit with tree $tree"
