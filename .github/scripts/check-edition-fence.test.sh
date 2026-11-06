#!/usr/bin/env bash
# Tests for check-edition-fence.sh. Run: bash .github/scripts/check-edition-fence.test.sh
# Builds throwaway git repositories; touches nothing in this one. The
# restricted-word cases use a made-up word, never a real list entry.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-edition-fence.sh"
word="zqxfencewordzq"
pass=0 failed=0

# report <name> <want rc> <got rc>
report() {
  if [[ "$3" -eq "$2" ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1 (exit $3, want $2)"; failed=$((failed + 1)); fi
}

# newrepo: a repo with a clean .gitignore and one Go module without replace.
newrepo() {
  local d
  d="$(mktemp -d)"
  git -C "$d" init -q -b main
  mkdir -p "$d/server" "$d/web/src"
  sed -n '/^# Extension mount points/,$p' "$here/../../.gitignore" > "$d/.gitignore"
  printf 'module example.com/api\n\ngo 1.25\n' > "$d/server/go.mod"
  git -C "$d" add -f .gitignore server/go.mod
  echo "$d"
}

# check <name> <want rc> [path content pairs...]; env FENCE_RESTRICTED_WORDS=$word.
check() {
  local name="$1" want="$2" d rc
  shift 2
  d="$(newrepo)"
  while [[ $# -ge 2 ]]; do
    mkdir -p "$d/$(dirname "$1")"; printf '%s' "$2" > "$d/$1"
    git -C "$d" add -f "$1"; shift 2
  done
  rc=0; (cd "$d" && FENCE_RESTRICTED_WORDS="$word" bash "$script" >/dev/null 2>&1) || rc=$?
  report "$name" "$want" "$rc"
}

check "clean tree" 0
check "mount point file tracked" 1 web/src/extensions/web.ts 'x'
check "route group tracked" 1 'web/src/app/(dashboard)/(extensions)/a/page.tsx' 'x'
check "console route group tracked" 1 'web/console/src/app/(console)/(extensions)/a/page.tsx' 'x'
check "replace in server/go.mod" 1 server/go.mod $'module example.com/api\n\nreplace example.com/x => ../x\n'
check "replace block in server/go.mod" 1 server/go.mod $'module example.com/api\n\nreplace (\n\texample.com/x => ../x\n)\n'
check "web direct mount import" 1 web/src/a.ts "import { x } from '@/extensions/web';"
check "web relative mount import" 1 web/src/a/b.tsx "import x from '../extensions/y';"
check "web alias import is fine" 0 web/src/a.ts "import { x } from '@extension/web';"
check "web default import is fine" 0 web/src/a.ts "import { x } from '@/extension-default/web';"
check "mount dir named in a non-config file" 1 web/src/b.ts "const p = 'src/extensions/';"
check "mount dir named in next.config" 0 web/next.config.ts "const p = 'src/extensions/';"
check "mount dir named in console next.config" 0 web/console/next.config.ts "const p = '../src/extensions';"
check "restricted word in a source file" 1 server/internal/x/a.go "package x // $word"
check "restricted word, other case" 1 docs/a.md "About $(printf '%s' "$word" | tr a-z A-Z)"
check "restricted word in a path" 1 "docs/$word.md" "x"

# Without a list, rule d is skipped (a restricted word passes) and says so.
d="$(newrepo)"; printf 'x %s\n' "$word" > "$d/a.md"; git -C "$d" add a.md
rc=0; out="$(cd "$d" && env -u FENCE_RESTRICTED_WORDS bash "$script" 2>&1)" || rc=$?
report "no list: rule d skipped" 0 "$rc"
if grep -q "rule d skipped" <<<"$out"; then report "no list: says so" 0 0; else report "no list: says so" 0 1; fi

# A local list in .git/info/restricted-words is used.
d="$(newrepo)"; printf 'x %s\n' "$word" > "$d/a.md"; git -C "$d" add a.md
mkdir -p "$d/.git/info"; printf '# local list\n%s\n' "$word" > "$d/.git/info/restricted-words"
rc=0; (cd "$d" && env -u FENCE_RESTRICTED_WORDS bash "$script" >/dev/null 2>&1) || rc=$?
report "local word list" 1 "$rc"

# The output never prints the matched word.
d="$(newrepo)"; printf 'x %s\n' "$word" > "$d/a.md"; git -C "$d" add a.md
out="$(cd "$d" && FENCE_RESTRICTED_WORDS="$word" bash "$script" 2>&1 || true)"
if grep -qi -- "$word" <<<"$out"; then report "output hides the word" 0 1; else report "output hides the word" 0 0; fi

# A .gitignore without the mount lines fails.
d="$(mktemp -d)"; git -C "$d" init -q -b main; : > "$d/.gitignore"; git -C "$d" add .gitignore
rc=0; (cd "$d" && bash "$script" >/dev/null 2>&1) || rc=$?
report ".gitignore missing mount lines" 1 "$rc"

# This repository passes (rule d only when the environment has a list).
rc=0; (cd "$here/../.." && bash "$script" >/dev/null 2>&1) || rc=$?
report "this repository" 0 "$rc"

echo "passed $pass, failed $failed"
[[ "$failed" -eq 0 ]]
