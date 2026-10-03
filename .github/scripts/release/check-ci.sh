#!/usr/bin/env bash
# check-ci.sh: is a commit's CI green? (api/docs/rfcs/RFC-037 §4.4)
#
#   check-ci.sh SHA                       exit 0 when every required check
#                                         passed on SHA, 1 otherwise
#   check-ci.sh --newest-green REF [--max N] [--repo DIR]
#                                         print the newest first-parent commit
#                                         of REF (at most N back, default 30)
#                                         whose required checks all passed
#
# A required check passes when its most recent run on the commit concluded
# "success". Missing, pending, cancelled, skipped and failed all count as red:
# a release is cut from a commit CI vouched for, nothing less.
#
# Environment:
#   REQUIRED_CHECKS  comma-separated check names (default: the branch
#                    protection set of develop and main)
#   GITHUB_REPOSITORY owner/repo for the API (set in Actions)
#   CHECK_RUNS_DIR   tests only: read check runs from $CHECK_RUNS_DIR/<sha>.json
#                    (a JSON array of {name, status, conclusion, id}) instead
#                    of the GitHub API
set -euo pipefail

REQUIRED_CHECKS="${REQUIRED_CHECKS:-API CI OK,Web CI OK,CodeQL OK,All-in-one OK,Secret Scanning,Workflow Lint}"

runs_json() { # SHA -> JSON array of check runs
  if [[ -n "${CHECK_RUNS_DIR:-}" ]]; then
    if [[ -f "$CHECK_RUNS_DIR/$1.json" ]]; then cat "$CHECK_RUNS_DIR/$1.json"; else echo '[]'; fi
    return
  fi
  : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
  gh api --paginate "repos/$GITHUB_REPOSITORY/commits/$1/check-runs?per_page=100" \
    --jq '.check_runs[] | {name, status, conclusion, id}' | jq -s '.'
}

# verdict SHA: prints "<name>\t<state>" per required check; exit 0 when all
# are success.
verdict() {
  local json
  json="$(runs_json "$1")"
  jq -r --arg req "$REQUIRED_CHECKS" '
    ($req | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $names
    | [ $names[] as $n
        | ([ .[] | select(.name == $n) ] | sort_by(.id) | last) as $r
        | { name: $n,
            state: (if $r == null then "missing"
                    elif $r.status != "completed" then $r.status
                    else ($r.conclusion // "unknown") end) } ]
    | (.[] | "\(.name)\t\(.state)"),
      (if all(.[]; .state == "success") then "__GREEN__" else "__RED__" end)
  ' <<<"$json" | {
    green=1
    while IFS= read -r line; do
      case "$line" in
        __GREEN__) ;;
        __RED__) green=0 ;;
        *) echo "$line" ;;
      esac
    done
    [[ $green -eq 1 ]]
  }
}

if [[ "${1:-}" == "--newest-green" ]]; then
  ref="${2:?--newest-green needs a ref}"
  shift 2
  max=30
  repo="."
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --max) max="$2"; shift ;;
      --repo) repo="$2"; shift ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
  done
  while IFS= read -r sha; do
    if verdict "$sha" >/dev/null; then
      echo "$sha"
      exit 0
    fi
    echo "not green: $sha" >&2
  done < <(git -C "$repo" rev-list --first-parent -n "$max" "$ref")
  echo "no commit with every required check green in the last $max of $ref" >&2
  exit 1
fi

sha="${1:?usage: check-ci.sh SHA | --newest-green REF}"
if verdict "$sha"; then
  echo "green: $sha"
else
  echo "NOT green: $sha (every required check must have succeeded)" >&2
  exit 1
fi
