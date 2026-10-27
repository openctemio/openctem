#!/usr/bin/env bash
# Tests for check-job-timeouts.sh. Run: bash .github/scripts/check-job-timeouts.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-job-timeouts.sh"
d="$(mktemp -d)"
pass=0 failed=0
check() { # <expect ok|fail> <name> <yaml>
  printf '%s\n' "$3" >"$d/w.yml"
  if bash "$script" "$d/w.yml" >/dev/null 2>&1; then got=ok; else got=fail; fi
  if [ "$got" = "$1" ]; then echo "ok:   $2"; pass=$((pass + 1)); else echo "FAIL: $2 (want $1, got $got)"; failed=$((failed + 1)); fi
}
check ok "every job has a timeout" 'on: push
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: true
  b:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: true'
check fail "one job lacks a timeout" 'on: push
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: true
  b:
    runs-on: ubuntu-latest
    steps:
      - run: true'
check fail "the last job lacks a timeout" 'jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: true'
check ok "a reusable-workflow call needs none" 'jobs:
  a:
    uses: ./.github/workflows/x.yml'
check fail "a step timeout does not count for the job" 'jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: true
        timeout-minutes: 5'
check fail "a timeout in a later top-level key does not count" 'jobs:
  a:
    runs-on: ubuntu-latest
env:
    timeout-minutes: 5'
check ok "comments and blank lines between jobs" 'jobs:
  # first
  a:
    runs-on: ubuntu-latest

    timeout-minutes: 5
  b:
    timeout-minutes: 5
    runs-on: ubuntu-latest'
check ok "no jobs key" 'name: x'
find "$d" -type f -name 'w.yml' -delete
rmdir "$d"
echo "pass=$pass failed=$failed"
[ "$failed" -eq 0 ]
