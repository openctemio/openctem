#!/usr/bin/env bash
# testlib.sh: tiny assertion helpers for the release script tests.
# Source it from a test_*.sh, call the assert_* helpers, end with `finish`.
set -uo pipefail

TESTS_RUN=0
TESTS_FAILED=0
export RELEASE_DIR
RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

assert_eq() { # name want got
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$2" != "$3" ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    want: %q\n    got:  %q\n' "$1" "$2" "$3"
  fi
}

assert_contains() { # name needle haystack
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$3" != *"$2"* ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    want to contain: %q\n    got: %s\n' "$1" "$2" "$3"
  fi
}

assert_not_contains() { # name needle haystack
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$3" == *"$2"* ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  FAIL %s\n    must not contain: %q\n    got: %s\n' "$1" "$2" "$3"
  fi
}

assert_rc() { # name want-rc command...
  local name="$1" want="$2" got
  shift 2
  "$@" >/dev/null 2>&1
  got=$?
  assert_eq "$name (exit code)" "$want" "$got"
}

# new_repo DIR: an empty git repository with a deterministic identity.
new_repo() {
  git init -q -b main "$1"
  git -C "$1" config user.name test
  git -C "$1" config user.email test@example.invalid
  git -C "$1" config commit.gpgsign false
  git -C "$1" config tag.gpgsign false
}

# commit DIR MESSAGE [FILE]: commit a change (touches FILE, default "f").
commit() {
  local f="${3:-f}"
  mkdir -p "$(dirname "$1/$f")"
  echo "$2 $RANDOM" >>"$1/$f"
  git -C "$1" add -A
  git -C "$1" commit -q -m "$2"
}

finish() {
  echo "  $TESTS_RUN assertion(s), $TESTS_FAILED failed"
  [[ $TESTS_FAILED -eq 0 ]]
}
