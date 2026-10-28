#!/usr/bin/env bash
# Tests for go-affected.py. Run: bash .github/scripts/go-affected.test.sh
# A scratch Go module laid out like the repository (api/ holds the module).
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/go-affected.py"
pass=0 failed=0
d="$(mktemp -d)"
m="$d/api"; mkdir -p "$m/a" "$m/b" "$m/c" "$m/d" "$m/e/testdata" "$m/configs"
printf 'module ex.test/api\n\ngo 1.21\n' >"$m/go.mod"
echo 'package a' >"$m/a/a.go"
printf 'package b\nimport _ "ex.test/api/a"\n' >"$m/b/b.go"
echo 'package c' >"$m/c/c.go"
echo 'package d' >"$m/d/d.go"
printf 'package d\nimport (\n"testing"\n_ "ex.test/api/b"\n)\nfunc TestX(t *testing.T) {}\n' >"$m/d/d_test.go"
echo 'package e' >"$m/e/e.go"
echo x >"$m/e/testdata/f.txt"
echo x >"$m/configs/x.yaml"

run() { # <want> <name> <file>...   (want: "-" for empty output)
  local want=$1 name=$2 got; shift 2
  printf '%s\n' "$@" >"$d/changed.txt"
  got="$(cd "$m" && GOFLAGS=-mod=mod python3 -I "$script" "$d/changed.txt" 2>/dev/null | paste -sd, -)"
  [ -n "$got" ] || got=-
  if [ "$got" = "$want" ]; then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (want $want, got $got)"; failed=$((failed + 1)); fi
}
P=ex.test/api
run "$P/a,$P/b,$P/d" "a leaf package reaches its importers and their test importers" api/a/a.go
run "$P/c" "an unrelated package affects only itself" api/c/c.go
run "$P/d" "a package nobody imports" api/d/d_test.go
run "$P/e" "testdata belongs to its package" api/e/testdata/f.txt
run ALL "go.mod changes everything" api/go.mod
run ALL "a Go file outside every package" api/nopkg/x.go
run - "web only" web/src/x.ts
run - "shared files change no Go package" .github/workflows/x.yml Makefile
run - "a top-level non-code file" api/Makefile
run - "a file outside any package that is not Go" api/configs/x.yaml
run "$P/a,$P/b,$P/c,$P/d" "several files" api/c/c.go api/a/a.go web/x
# an unreadable list or a failed go list fails toward ALL
got="$(cd "$d" && python3 -I "$script" "$d/missing.txt" 2>/dev/null)"
if [ "$got" = ALL ]; then echo "ok:   a missing input fails toward ALL"; pass=$((pass + 1)); else echo "FAIL: missing input (got $got)"; failed=$((failed + 1)); fi
echo "$pass passed, $failed failed"
[ "$failed" -eq 0 ]
