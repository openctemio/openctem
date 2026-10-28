#!/usr/bin/env bash
# Plans this run's DB-backed Go test shards, once, so every shard reads the
# same plan (the `spec` job of api-ci.yml calls it; run from api/).
#
# Writes to $GO_PLAN_DIR (uploaded as the `go-plan` artifact):
#   mode.txt        `affected` (only the packages in affected.txt run) or `all`
#   affected.txt    the affected import paths, when the mode is `affected`
#   durations.json  {"<import path>": seconds} from the latest run that
#                   recorded them (the `go-durations` artifact), when found
# and to $GITHUB_OUTPUT: test_matrix, the shard list of `Tests (Postgres +
# Redis)`.
#
# Tiers (EVENT, FULL as api-ci.yml's `changes` job reports them):
#   merge_group, push   everything, 8 shards, with the race detector
#   pull_request, full  everything, 8 shards, no race detector (`ci:full`
#                       label or a changed CI definition)
#   pull_request        the packages the change can affect (go-affected.sh),
#                       as many shards as that needs (1 to 6), no race detector
# The race detector runs in the merge queue and on push only; a PR gets the
# same tests without it (about half the runner time).
#
# Env: EVENT, FULL, BASE_REF, REPO, GH_TOKEN (actions: read, for durations),
#      GO_PLAN_DIR.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="${GO_PLAN_DIR:?}"
mkdir -p "$dir"
echo all > "$dir/mode.txt"

# The latest recorded durations. A failure here only costs balance.
[ -z "${GH_TOKEN:-}" ] || bash "$here/latest-artifact.sh" go-durations durations.json "$dir/durations.json" || true

n=6 race=false
if [ "${EVENT:-}" != pull_request ]; then
  n=8 race=true
elif [ "${FULL:-}" = true ]; then
  n=8
else
  list=""
  git fetch --no-tags --quiet origin "${BASE_REF:?}" || true
  if list="$(bash "$here/go-affected.sh" "origin/${BASE_REF}")" && [ "$(head -1 <<<"$list")" != ALL ]; then
    echo affected > "$dir/mode.txt"
    printf '%s' "$list" | { grep -v '^$' || true; } > "$dir/affected.txt"
    count="$(wc -l < "$dir/affected.txt")"
    # About ten affected packages per shard; the biggest package alone (tests/
    # integration, split by test name over the shards) is worth ten.
    n=$(((count + 9) / 10)); [ "$n" -ge 1 ] || n=1; [ "$n" -le 6 ] || n=6
    echo "affected packages: $count -> $n shards"
    head -50 "$dir/affected.txt"
  else
    echo "the change cannot be narrowed: the whole suite"
  fi
fi

m="$(jq -nc --argjson n "$n" --argjson race "$race" '[range($n) | {shard: ., total: $n, race: $race}]')"
echo "test_matrix=$m" | tee -a "${GITHUB_OUTPUT:-/dev/stdout}"
echo "mode: $(cat "$dir/mode.txt")"
