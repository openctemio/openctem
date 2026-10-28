#!/usr/bin/env bash
# Stops CI work that can no longer change the outcome once a job has failed.
# Called from the last step of every job behind an "... OK" gate, only when
# that job failed (.github/actions/fail-fast, `if: failure()`).
#
#   merge_group   the group is doomed (its required check will fail and the
#                 queue ejects it), so cancel every OTHER unfinished
#                 merge_group run of the same merge-group head commit. Runs of
#                 any other commit or event are never touched.
#   anything else nothing.
#
# This run is never cancelled: the job calling this script is still running,
# and cancelling its run turns that job's conclusion from "failure" into
# "cancelled". The failure then shows only in annotations, and tooling that
# looks for a failed job (the queue keeper) re-queues a broken group as if a
# runner had been lost. The other runs' gates fail at once after their
# cancel, so the queue still ejects the group in minutes; this run's gate
# fails once its remaining jobs finish.
#
# The gates (`API CI OK`, `Web CI OK`, `E2E OK`, `All-in-one OK`) run with
# `if: always()`, so they still run after the cancel and fail on the
# failed/cancelled jobs.
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
    ;;
  *)
    echo "fail-fast: $EVENT: nothing cancelled"
    ;;
esac
exit 0
