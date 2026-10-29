#!/usr/bin/env bash
# Tests go-affected.sh on a throw-away module: a <- b <- c, d alone, a
# package e whose external test imports a, an embedded file under d.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q -b main .
git config user.email t@example.test; git config user.name t
mkdir -p api/a api/b api/c api/d/tpl api/e api/migrations api/docs api/changelog.d web
printf 'module example.test/m\n\ngo 1.22\n' > api/go.mod
printf 'package a\n\nfunc A() int { return 1 }\n' > api/a/a.go
printf 'package b\n\nimport "example.test/m/a"\n\nfunc B() int { return a.A() }\n' > api/b/b.go
printf 'package c\n\nimport "example.test/m/b"\n\nfunc C() int { return b.B() }\n' > api/c/c.go
printf 'package d\n\nfunc D() int { return 4 }\n' > api/d/d.go
echo x > api/d/tpl/t.html
printf 'package e\n' > api/e/e.go
printf 'package e_test\n\nimport "example.test/m/a"\n\nvar _ = a.A\n' > api/e/e_test.go
echo 1 > api/migrations/1.sql; echo d > api/docs/x.md; echo f > api/changelog.d/f.md; echo w > web/w.ts; echo r > README.md
git add -A; git commit -q -m base
run() { (cd api && bash "$here/go-affected.sh" main | paste -sd' '); }
expect() { local got; got="$(run)"; [ "$got" = "$2" ] || { echo "FAIL $1: got '$got', want '$2'" >&2; exit 1; }; echo "ok $1"; }
change() { git checkout -q -B work main; "$@"; git add -A; git commit -q -m c; }

change sh -c 'echo "// x" >> api/a/a.go'
expect "a ripples to b, c and the package whose test imports it" "example.test/m/a example.test/m/b example.test/m/c example.test/m/e"
change sh -c 'echo "// x" >> api/c/c.go'
expect "a leaf changes alone" "example.test/m/c"
change sh -c 'echo y > api/d/tpl/t.html'
expect "an embedded file belongs to the nearest package" "example.test/m/d"
change sh -c 'echo "// x" >> api/e/e_test.go'
expect "a test file changes its package" "example.test/m/e"
change sh -c 'echo 2 > api/migrations/2.sql'
expect "a migration runs everything" "ALL"
change sh -c 'echo "// x" >> api/go.mod'
expect "go.mod runs everything" "ALL"
change sh -c 'mkdir -p deploy && echo 1 > deploy/x'
expect "a shared file outside api runs everything" "ALL"
change sh -c 'echo y >> api/docs/x.md; echo y >> api/changelog.d/f.md; echo y >> web/w.ts; echo y >> README.md'
expect "docs, changelog and web only select nothing" ""
change sh -c 'echo "// x" >> api/b/b.go; echo y >> api/changelog.d/f.md'
expect "a fragment beside code does not widen the set" "example.test/m/b example.test/m/c"
echo "go-affected: all passed"
