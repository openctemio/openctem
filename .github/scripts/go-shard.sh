#!/usr/bin/env bash
# Splits the API Go test suite into shards that run as parallel CI jobs.
#
# Run from api/. Two kinds of shard, because one package (tests/unit) holds
# most of the tests and alone takes longer than all the others together:
#
#   go-shard.sh pkgs <i> <n>   package import paths for shard i of n (one per
#                              line). Every package except tests/unit.
#   go-shard.sh unit <i> <n>   a `go test -run` regexp selecting shard i of n of
#                              the top-level tests in tests/unit.
#   go-shard.sh check <np> <nu>  proves that the pkgs shards (np) and unit
#                              shards (nu) together cover every package and
#                              every top-level test exactly once; exit 1 if not.
#
# The assignment is a pure function of the package / test names, so a shard
# never depends on what another shard did. The three slowest packages are
# pinned to different pkgs shards; the rest are spread by a checksum of the
# import path.
set -euo pipefail

UNIT=github.com/openctemio/openctem/api/tests/unit
PIN_0=github.com/openctemio/openctem/api/tests/integration
PIN_1=github.com/openctemio/openctem/api/internal/infra/http/routes
PIN_2=github.com/openctemio/openctem/api/internal/infra/postgres

all_pkgs() { go list ./... | grep -vxF "$UNIT" | LC_ALL=C sort; }

pkg_shard() { # <pkg> <n> -> shard index
  case "$1" in
    "$PIN_0") echo $((0 % $2)) ;;
    "$PIN_1") echo $((1 % $2)) ;;
    "$PIN_2") echo $((2 % $2)) ;;
    *) echo $(($(printf '%s' "$1" | cksum | cut -d' ' -f1) % $2)) ;;
  esac
}

pkgs() { # <i> <n>
  local p
  while IFS= read -r p; do
    [ "$(pkg_shard "$p" "$2")" = "$1" ] && echo "$p"
  done < <(all_pkgs)
  return 0
}

unit_tests() { # all top-level tests of tests/unit, sorted
  go test -list '.*' ./tests/unit | grep -E '^(Test|Example|Fuzz)' | LC_ALL=C sort
}

unit_names() { # <i> <n>
  unit_tests | awk -v i="$1" -v n="$2" '(NR - 1) % n == i'
}

unit() { # <i> <n> -> -run regexp
  local names
  names="$(unit_names "$1" "$2" | paste -sd'|')"
  [ -n "$names" ] || { echo "no tests in unit shard $1/$2" >&2; exit 1; }
  echo "^(${names})\$"
}

check() { # <np> <nu>
  local np=$1 nu=$2 i got want
  want="$(all_pkgs)"
  got="$(for ((i = 0; i < np; i++)); do pkgs "$i" "$np"; done | LC_ALL=C sort)"
  [ "$got" = "$want" ] || { echo "pkgs shards do not cover every package exactly once" >&2; diff <(echo "$want") <(echo "$got") >&2 || true; exit 1; }
  want="$(unit_tests)"
  got="$(for ((i = 0; i < nu; i++)); do unit_names "$i" "$nu"; done | LC_ALL=C sort)"
  [ "$got" = "$want" ] || { echo "unit shards do not cover every test exactly once" >&2; exit 1; }
  echo "shards cover $(echo "$want" | wc -l) unit tests and $(all_pkgs | wc -l) other packages exactly once"
}

case "${1:-}" in
  pkgs) pkgs "${2:?shard}" "${3:?total}" ;;
  unit) unit "${2:?shard}" "${3:?total}" ;;
  check) check "${2:?pkgs shards}" "${3:?unit shards}" ;;
  *) echo "usage: go-shard.sh pkgs|unit <i> <n> | check <np> <nu>" >&2; exit 2 ;;
esac
