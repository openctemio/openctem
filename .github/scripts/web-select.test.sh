#!/usr/bin/env bash
# Tests the classification half of web-select.sh in a throw-away repository.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main .
git config user.email t@example.test; git config user.name t
mkdir -p web/src/lib web/src/test web/e2e web/docs web/scripts api/x .github
for f in web/src/lib/a.ts web/src/test/setup.ts web/e2e/a.spec.ts web/docs/a.md web/scripts/s.sh web/package.json api/x/a.go .github/w.yml web/console-n; do echo 1 > "$f"; done
git add -A; git commit -q -m base
export WEB_SELECT_NO_LIST=1
check() { # <expect> <file>
  git checkout -q -B w main; echo 2 >> "$2"; git add -A; git commit -q -m c
  got="$(cd web && bash "$here/web-select.sh" main)"
  [ "$got" = "$1" ] || { echo "FAIL $2: got '$got', want '$1'" >&2; exit 1; }
  echo "ok $2 -> $1"
}
check narrow web/src/lib/a.ts
check narrow web/e2e/a.spec.ts
check narrow web/docs/a.md
check narrow api/x/a.go
check ALL web/src/test/setup.ts
check ALL web/package.json
check ALL web/scripts/s.sh
check ALL .github/w.yml
echo "web-select: all passed"
