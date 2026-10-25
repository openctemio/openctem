#!/usr/bin/env bash
# Splits the API Go test suite into shards that run as parallel CI jobs.
#
# Run from api/. A few packages hold most of the run time and run their tests
# one after another, so a package-level split leaves one shard far behind the
# others (tests/integration alone took about 13 minutes of a 20 minute shard).
# Those packages (SPLIT below) are split by top-level test name over every
# shard; every other package goes whole to one shard, by a checksum of its
# import path.
#
#   go-shard.sh plan <i> <n>   the `go test` invocations of shard i of n, one
#                              per line, run in order by go-shard-run.sh:
#                                pkgs <import path>...
#                                run <import path> <-run regexp>
#   go-shard.sh check <n>...   proves that for every n given, the shards cover
#                              every package and every top-level test of a
#                              SPLIT package exactly once; exit 1 if not.
#
# The assignment is a pure function of the package and test names, so a shard
# never depends on what another shard did. Each SPLIT slice runs in its own
# `go test` process, one after another, so it has the database to itself as
# before (these packages never ran next to another package's tests).
set -euo pipefail

MOD=github.com/openctemio/openctem/api
SPLIT=(
  "$MOD/tests/unit"
  "$MOD/tests/integration"
  "$MOD/internal/infra/http/routes"
  "$MOD/internal/infra/postgres"
)

is_split() { local s; for s in "${SPLIT[@]}"; do [ "$1" = "$s" ] && return 0; done; return 1; }

OTHER=""
other_pkgs() { # every package except the SPLIT ones, sorted (listed once per run)
  local p
  if [ -z "$OTHER" ]; then
    OTHER="$(while IFS= read -r p; do is_split "$p" || echo "$p"; done < <(go list ./... | LC_ALL=C sort))"
  fi
  printf '%s\n' "$OTHER"
}

pkg_shard() { # <pkg> <n> -> shard index
  echo $(($(printf '%s' "$1" | cksum | cut -d' ' -f1) % $2))
}

pkgs() { # <i> <n>
  local p
  while IFS= read -r p; do
    [ "$(pkg_shard "$p" "$2")" = "$1" ] && echo "$p"
  done < <(other_pkgs)
  return 0
}

declare -A LISTED=()
tests_of() { # <pkg>: its top-level tests, sorted (listed once per run)
  # Read from the source, not `go test -list`: listing compiles the test
  # binary (without -race, so the shard compiled it twice) and cost each shard
  # about 90 seconds. A top-level test is a file-level `func TestX(`; a name
  # from a file a build tag leaves out only makes -run match nothing more.
  # `check` proves every test `go test -list` reports is in this list.
  local dir
  if [ -z "${LISTED[$1]+x}" ]; then
    dir=".${1#"$MOD"}"
    LISTED[$1]="$(grep -hoE '^func (Test|Example|Fuzz)[A-Za-z0-9_]*\(' "$dir"/*_test.go 2>/dev/null \
      | sed -E 's/^func //; s/\($//' | grep -vx 'TestMain' | LC_ALL=C sort -u || true)"
  fi
  printf '%s\n' "${LISTED[$1]}" | grep -v '^$' || true
}

compiled_tests_of() { # <pkg>: what `go test -list` reports (compiles the package)
  local out
  out="$(go test -list '.*' "$1")" || { echo "go test -list $1 failed" >&2; return 1; }
  printf '%s\n' "$out" | grep -E '^(Test|Example|Fuzz)' | LC_ALL=C sort || true
}

prefetch() { # fill both lists in this shell, so the subshells below reuse them
  local p
  other_pkgs >/dev/null
  for p in "${SPLIT[@]}"; do tests_of "$p" >/dev/null; done
}

slice() { # <pkg> <k> <i> <n>: the tests of shard i; package k starts at shard k
  tests_of "$1" | awk -v k="$2" -v i="$3" -v n="$4" '(NR - 1 + k) % n == i'
}

plan() { # <i> <n>
  local i=$1 n=$2 k names p
  [ "$i" -ge 0 ] && [ "$i" -lt "$n" ] || { echo "shard $i is not in 0..$((n - 1))" >&2; exit 2; }
  prefetch
  for k in "${!SPLIT[@]}"; do
    p=${SPLIT[$k]}
    names="$(slice "$p" "$k" "$i" "$n" | paste -sd'|')"
    [ -n "$names" ] && echo "run $p ^(${names})\$"
  done
  names="$(pkgs "$i" "$n" | paste -sd' ')"
  [ -n "$names" ] && echo "pkgs $names"
  return 0
}

check() { # <n>...
  local n i p k got want missing compiled
  prefetch
  for n in "$@"; do
    want="$(other_pkgs)"
    got="$(for ((i = 0; i < n; i++)); do pkgs "$i" "$n"; done | LC_ALL=C sort)"
    [ "$got" = "$want" ] || { echo "$n shards: packages are not covered exactly once" >&2; diff <(echo "$want") <(echo "$got") >&2 || true; exit 1; }
    for k in "${!SPLIT[@]}"; do
      p=${SPLIT[$k]}
      want="$(tests_of "$p")"
      [ -n "$want" ] || { echo "$p has no tests; drop it from SPLIT" >&2; exit 1; }
      if [ "$n" = "$1" ]; then # once: the source list holds every compiled test
        compiled="$(compiled_tests_of "$p")" || exit 1
        missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$compiled") <(printf '%s\n' "$want"))"
        [ -z "$missing" ] || { echo "$p: tests not found in the source list (go-shard.sh tests_of):" >&2; echo "$missing" >&2; exit 1; }
      fi
      got="$(for ((i = 0; i < n; i++)); do slice "$p" "$k" "$i" "$n"; done | LC_ALL=C sort)"
      [ "$got" = "$want" ] || { echo "$n shards: the tests of $p are not covered exactly once" >&2; exit 1; }
    done
    echo "$n shards cover $(other_pkgs | wc -l) packages whole and ${#SPLIT[@]} packages by test, each exactly once"
  done
}

case "${1:-}" in
  plan) plan "${2:?shard}" "${3:?total}" ;;
  check) shift; [ "$#" -gt 0 ] || { echo "usage: go-shard.sh check <n>..." >&2; exit 2; }; check "$@" ;;
  *) echo "usage: go-shard.sh plan <i> <n> | check <n>..." >&2; exit 2 ;;
esac
