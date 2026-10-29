#!/usr/bin/env bash
# Plans this run's DB-backed Go test shards, once, so every shard reads the
# same plan (the `spec` job of api-ci.yml calls it; run from api/).
#
# Writes to $GO_PLAN_DIR (uploaded as the `go-plan` artifact):
#   mode.txt        `all` (kept so a shard can also run a narrowed plan)
#   durations.json  {"<import path>": seconds} from the latest run that
#                   recorded them (the `go-durations` artifact), when found
# and to $GITHUB_OUTPUT: test_matrix, the shard list of `Tests (Postgres +
# Redis)`.
#
# Only the full tier runs these shards (a pull request without `ci:full` runs the
# `Unit tests` job instead, over the packages go-affected.sh selects), so the
# plan is always the whole suite: 8 shards with the race detector. The merge
# queue is authoritative for it.
#
# Env: GH_TOKEN (actions: read, for durations), GO_PLAN_DIR.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dir="${GO_PLAN_DIR:?}"
mkdir -p "$dir"
echo all > "$dir/mode.txt"

# The latest recorded durations. A failure here only costs balance.
[ -z "${GH_TOKEN:-}" ] || bash "$here/latest-artifact.sh" go-durations durations.json "$dir/durations.json" || true

n=8 race=true

m="$(jq -nc --argjson n "$n" --argjson race "$race" '[range($n) | {shard: ., total: $n, race: $race}]')"
echo "test_matrix=$m" | tee -a "${GITHUB_OUTPUT:-/dev/stdout}"
echo "mode: $(cat "$dir/mode.txt")"
