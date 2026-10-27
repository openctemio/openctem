#!/usr/bin/env bash
# Stops CI work that can no longer change the outcome once a job has failed.
# Called from the last step of every job behind an "... OK" gate, only when
# that job failed (.github/actions/fail-fast, `if: failure()`).
#
#   merge_group   the group is doomed (its required check will fail and the
#                 queue ejects it), so cancel every unfinished merge_group run
#                 of the same merge-group head commit, this run last. Runs of
#                 any other commit or event are never touched.
#   pull_request  cancel the rest of this run only; other workflows keep
#                 running so lint and test failures still show separately.
#                 A fork PR has a read-only token: nothing to do.
#   anything else nothing (a push is the branch's baseline).
#
# The gates (`API CI OK`, `Web CI OK`, `E2E OK`, `All-in-one OK`) run with
# `if: always()`, so they still run after the cancel and fail on the
# failed/cancelled jobs: the queue sees the failure in minutes.
#
# Never fails the job further: every API error is a warning.
#
# Env: GH_TOKEN, REPO (owner/name), EVENT, RUN_ID, HEAD_SHA (merge_group head),
#      HEAD_REPO (pull_request head repository).
# Tests: .github/scripts/fail-fast.test.sh
set -uo pipefail

: "${REPO:?}" "${EVENT:?}" "${RUN_ID:?}"

cancel() { # <run id>
  if gh api -X POST "repos/$REPO/actions/runs/$1/cancel" >/dev/null 2>&1; then
    echo "fail-fast: cancelled run $1"
  else
    # 409: already finished or cancelling; 403: read-only token.
    echo "::warning::fail-fast: could not cancel run $1"
  fi
}

if ! [[ "$RUN_ID" =~ ^[0-9]+$ ]]; then
  echo "::warning::fail-fast: bad run id"; exit 0
fi

case "$EVENT" in
  merge_group)
    sha="${HEAD_SHA:-}"
    if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
      echo "::warning::fail-fast: no merge-group head commit"; exit 0
    fi
    if ! ids="$(gh api "repos/$REPO/actions/runs?head_sha=$sha&event=merge_group&per_page=100" \
      --jq ".workflow_runs[] | select(.head_sha == \"$sha\" and .event == \"merge_group\" and .status != \"completed\") | .id" 2>/dev/null)"; then
      echo "::warning::fail-fast: could not list the runs of $sha"
      ids=""
    fi
    for id in $ids; do
      [[ "$id" =~ ^[0-9]+$ ]] || continue
      [ "$id" = "$RUN_ID" ] && continue
      cancel "$id"
    done
    cancel "$RUN_ID"
    ;;
  pull_request)
    if [ "${HEAD_REPO:-}" != "$REPO" ]; then
      echo "fail-fast: fork pull request, read-only token: nothing cancelled"; exit 0
    fi
    cancel "$RUN_ID"
    ;;
  *)
    echo "fail-fast: $EVENT: nothing cancelled"
    ;;
esac
exit 0
