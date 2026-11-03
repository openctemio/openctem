#!/usr/bin/env bash
# Tests web-test-shards.sh in a throw-away repository with a local "origin".
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
git init -q --bare -b main "$tmp/origin.git"
git clone -q "$tmp/origin.git" "$tmp/w" 2>/dev/null
cd "$tmp/w"
git config user.email t@example.test; git config user.name t
mkdir -p web/src/lib web/scripts
echo 1 > web/src/lib/a.ts; echo 1 > web/scripts/s.sh
git add -A; git commit -q -m base; git push -q origin main
check() { # <want> <event> <full> <file>
  git checkout -q -B w main; echo 2 >> "$4"; git add -A; git commit -q -m c
  got="$(EVENT="$2" FULL="$3" BASE_REF=main GITHUB_OUTPUT=/dev/stdout bash "$here/web-test-shards.sh")"
  [ "$got" = "shards=$1" ] || { echo "FAIL $2/$3/$4: got '$got', want 'shards=$1'" >&2; exit 1; }
  echo "ok $2 full=$3 $4 -> $1"
}
check '[1]' pull_request false web/src/lib/a.ts
check '[1,2,3]' pull_request true web/src/lib/a.ts
check '[1,2,3]' pull_request false web/scripts/s.sh
check '[1,2,3]' merge_group false web/src/lib/a.ts
check '[1,2,3]' push false web/src/lib/a.ts
echo "web-test-shards: all passed"
