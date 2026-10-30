#!/usr/bin/env bash
# Runs shard i of n of the API Go test suite (the plan from go-shard.sh), one
# `go test` process after another, from api/.
#
#   go-shard-run.sh <i> <n> <json-out> [go test flags...]
#
# Every process writes `go test -json` lines; all of them end up in <json-out>
# (for check-db-test-skips.sh) and the readable log is printed as it runs.
# With -coverprofile=<file> among the flags, each process writes its own
# profile and the profiles are merged into <file> at the end. The exit code is
# non-zero when any process failed; every process runs regardless.
set -uo pipefail

i=${1:?shard} n=${2:?total} out=${3:?json output}
shift 3
flags=() cover=""
for f in "$@"; do
  case "$f" in
    -coverprofile=*) cover=${f#-coverprofile=} ;;
    *) flags+=("$f") ;;
  esac
done

here=$(cd "$(dirname "$0")" && pwd)
mapfile -t plan < <(bash "$here/go-shard.sh" plan "$i" "$n") || exit 2
if [ "${#plan[@]}" -eq 0 ]; then
  # An affected-only run can leave a shard with nothing to do; a full run
  # never can (the check proves every shard has work), so it stays an error.
  [ -n "${GO_SHARD_AFFECTED:-}" ] || { echo "go-shard-run: shard $i/$n is empty" >&2; exit 2; }
  echo "go-shard-run: shard $i/$n has no affected package; nothing to run"
  : >"$out"
  [ -z "$cover" ] || echo "mode: atomic" >"$cover"
  exit 0
fi

: >"$out"
rc=0 step=0 profiles=()
for line in "${plan[@]}"; do
  step=$((step + 1))
  kind=${line%% *} rest=${line#* }
  if [ "$kind" = run ]; then
    args=(-run "${rest#* }" "${rest%% *}")
    label="${rest%% *} (part $((i + 1)) of $n)"
  else
    read -ra args <<<"$rest"
    label="${#args[@]} packages"
  fi
  prof=()
  if [ -n "$cover" ]; then
    prof=(-coverprofile="$cover.$step")
    profiles+=("$cover.$step")
  fi
  echo "::group::go test $label"
  go test -json "${flags[@]}" "${prof[@]}" "${args[@]}" \
    | tee -a "$out" \
    | jq -Rrj '. as $l | (try fromjson catch null) as $e
        | if $e == null then $l + "\n"
          elif ($e.Action == "output" or $e.Action == "build-output") then $e.Output
          else empty end'
  status=${PIPESTATUS[0]}
  echo "::endgroup::"
  if [ "$status" != 0 ]; then
    echo "::error::go test $label failed (exit $status)"
    rc=1
  fi
done

if [ -n "$cover" ]; then
  mode=$(head -qn1 "${profiles[@]}" 2>/dev/null | head -n1)
  { echo "${mode:-mode: atomic}"; tail -q -n +2 "${profiles[@]}" 2>/dev/null; } >"$cover"
fi
exit "$rc"
