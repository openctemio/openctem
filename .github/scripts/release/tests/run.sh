#!/usr/bin/env bash
# run.sh: run every test_*.sh next to it; exit 1 if any failed.
# Each test file is a plain bash script that sources testlib.sh.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0
for t in "$HERE"/test_*.sh; do
  echo "== $(basename "$t")"
  if ! bash "$t"; then
    failed=$((failed + 1))
  fi
done
if [[ $failed -gt 0 ]]; then
  echo "$failed test file(s) failed"
  exit 1
fi
echo "all release script tests passed"
