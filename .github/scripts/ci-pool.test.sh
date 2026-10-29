#!/usr/bin/env bash
# Tests ci-pool.sh: the share applies to run_id modulo 100; bad input falls back.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fails=0
pick() { RUN_ID="$1" SHARE="$2" GITHUB_OUTPUT=/dev/stdout bash "$here/ci-pool.sh" 2>/dev/null; }
expect() { # run_id share want
  local got; got="$(pick "$1" "$2")"
  if [ "$got" != "pool=$3" ]; then echo "FAIL: run $1 share '$2': got $got, want pool=$3"; fails=$((fails + 1)); else echo "ok: run $1 share '$2' -> $3"; fi
}
expect 1000 20 openctem-ci      # 00 < 20
expect 1019 20 openctem-ci      # 19 < 20
expect 1020 20 ubuntu-latest    # 20 is not below 20
expect 1099 20 ubuntu-latest
expect 1019 '' openctem-ci      # default 20
expect 1020 '' ubuntu-latest
expect 1019 abc openctem-ci     # invalid -> default
expect 1019 101 openctem-ci     # out of range -> default
expect 1019 -5 openctem-ci
expect 1050 0 ubuntu-latest     # 0 = split off
expect 1000 0 ubuntu-latest
expect 1099 100 openctem-ci     # 100 = everything
expect 1007 08 openctem-ci      # leading zero is decimal
expect 1009 8 ubuntu-latest
expect '' 50 ubuntu-latest      # no run id -> hosted
expect x7 50 ubuntu-latest
# Distribution: a share of S percent sends S of every 100 consecutive runs.
n=0; for i in $(seq 5000 5099); do [ "$(pick "$i" 35)" = pool=openctem-ci ] && n=$((n + 1)); done
if [ "$n" -ne 35 ]; then echo "FAIL: 35% of 100 runs gave $n"; fails=$((fails + 1)); else echo "ok: 35% of 100 consecutive runs"; fi
if [ "$fails" -gt 0 ]; then echo "$fails failure(s)"; exit 1; fi
echo "all ci-pool cases pass"
