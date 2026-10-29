#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main .
git config user.email t@example.test; git config user.name t
mkdir -p web/src/a/__tests__ web/e2e web/src/test; echo 1 > web/src/a/x.tsx
git add -A; git commit -q -m base; base="$(git rev-parse HEAD)"
check() { # <expect> <files...>
  want="$1"; shift
  git checkout -q -B w "$base"; for f in "$@"; do mkdir -p "$(dirname "$f")"; echo 2 >> "$f"; done
  git add -A; git commit -q -m c
  got="$(EVENT=push BEFORE="$base" bash "$here/web-build-needed.sh")"
  [ "$got" = "$want" ] || { echo "FAIL $*: got $got, want $want" >&2; exit 1; }
  echo "ok $* -> $want"
}
check false web/src/a/__tests__/t.test.tsx web/e2e/a.spec.ts README.md
check true web/src/a/x.tsx
check true web/src/a/__tests__/t.test.tsx web/package.json
check true .github/workflows/web-ci.yml
[ "$(EVENT=pull_request BEFORE=x bash "$here/web-build-needed.sh")" = true ] || exit 1
[ "$(EVENT=push BEFORE=0000000000000000000000000000000000000000 bash "$here/web-build-needed.sh")" = true ] || exit 1
echo "web-build-needed: all passed"
