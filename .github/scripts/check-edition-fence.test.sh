#!/usr/bin/env bash
# Tests for check-edition-fence.sh. Run: bash .github/scripts/check-edition-fence.test.sh
# Builds throwaway git repositories; touches nothing in this one. The brand
# word is read from the script under test so this file never repeats it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-edition-fence.sh"
brand="$(sed -n 's/^brand_words=(\(.*\))$/\1/p' "$script" | awk '{print $1}')"
[[ -n "$brand" ]] || { echo "FAIL: cannot read the brand list"; exit 1; }
pass=0 failed=0

# case <name> <want rc> <path> <content> [more path content pairs...]
# The base repo has a clean .gitignore, the overlay README and one Go file.
check() {
  local name="$1" want="$2" d rc
  shift 2
  d="$(mktemp -d)"
  git -C "$d" init -q -b main
  mkdir -p "$d/api/ee" "$d/api/cmd/server" "$d/web/src"
  sed -n '/^# Enterprise overlay/,$p' "$here/../../.gitignore" > "$d/.gitignore"
  echo "placeholder" > "$d/api/ee/README.md"
  printf 'package main\n' > "$d/api/cmd/server/main.go"
  while [[ $# -ge 2 ]]; do
    mkdir -p "$d/$(dirname "$1")"; printf '%s' "$2" > "$d/$1"
    git -C "$d" add -f "$1"; shift 2
  done
  git -C "$d" add -f .gitignore api/ee/README.md api/cmd/server/main.go
  rc=0; (cd "$d" && bash "$script" >/dev/null 2>&1) || rc=$?
  if [[ "$rc" -eq "$want" ]]; then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (exit $rc, want $want)"; failed=$((failed + 1)); fi
}

check "clean tree" 0
check "overlay file tracked" 1 api/ee/billing/x.go 'package billing'
check "web overlay file tracked" 1 'web/src/app/(ee)/a/page.tsx' 'x'
check "console overlay file tracked" 1 web/console/src/ee/a.ts 'x'
check "go imports overlay without tag" 1 api/cmd/server/a.go $'package main\nimport _ "github.com/openctemio/openctem/api/ee/billing"\n'
check "go imports private module without tag" 1 api/cmd/server/a.go $'package main\nimport _ "github.com/exploopio/x/y"\n'
check "go imports overlay with tag in the switch" 0 api/cmd/server/edition_ee.go $'//go:build ee\n\npackage main\nimport _ "github.com/openctemio/openctem/api/ee/billing"\n'
check "ee tag outside the switch file" 1 api/internal/x/a.go $'//go:build ee\n\npackage x\n'
check "ee in a combined tag outside the switch" 1 api/internal/x/a.go $'//go:build linux && ee\n\npackage x\n'
check "other tag is fine" 0 api/internal/x/a.go $'//go:build linux\n\npackage x\n'
check "word ee in a package name is fine" 0 api/internal/x/a.go $'package x\n// see ee docs\n'
check "web direct overlay import" 1 web/src/a.ts "import { x } from '@/ee/legal-hold';"
check "web relative overlay import" 1 web/src/a/b.tsx "import x from '../ee/y';"
check "web alias import is fine" 0 web/src/a.ts "import { x } from '@ee/legal-hold';"
check "web ee-stub import is fine" 0 web/src/a.ts "import { x } from '@/ee-stub/y';"
check "overlay dir named in a non-config file" 1 web/src/b.ts "const p = 'src/ee/';"
check "overlay dir named in next.config" 0 web/next.config.mjs "const p = 'src/ee/';"
check "brand in a source file" 1 api/internal/x/a.go "package x // $brand"
check "brand in a doc, other case" 1 docs/a.md "About $(printf '%s' "$brand" | tr a-z A-Z)"
check "brand in a path" 1 "docs/$brand.md" "x"

# A .gitignore without the overlay lines fails.
d="$(mktemp -d)"; git -C "$d" init -q -b main; : > "$d/.gitignore"; git -C "$d" add .gitignore
rc=0; (cd "$d" && bash "$script" >/dev/null 2>&1) || rc=$?
if [[ "$rc" -eq 1 ]]; then echo "ok:   .gitignore missing overlay lines"; pass=$((pass + 1)); else echo "FAIL: .gitignore (exit $rc)"; failed=$((failed + 1)); fi

# This repository passes.
rc=0; (cd "$here/../.." && bash "$script" >/dev/null 2>&1) || rc=$?
if [[ "$rc" -eq 0 ]]; then echo "ok:   this repository"; pass=$((pass + 1)); else echo "FAIL: this repository (exit $rc)"; failed=$((failed + 1)); fi

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
