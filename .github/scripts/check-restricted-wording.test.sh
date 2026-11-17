#!/usr/bin/env bash
# Tests for check-restricted-wording.sh. Run: bash .github/scripts/check-restricted-wording.test.sh
# Uses made-up rules and throwaway git repositories; touches nothing in this one.
set -u
script="$(cd "$(dirname "$0")" && pwd)/check-restricted-wording.sh"
d="$(mktemp -d)"; trap 'find "$d" -delete' EXIT
pass=0 failed=0
ok() { echo "ok:   $1"; pass=$((pass + 1)); }
no() { echo "FAIL: $1"; failed=$((failed + 1)); }

rules=$'# made-up rules\nzz-forbidden-[0-9]+\n\n  (^|[^a-z])qq blocked([^a-z]|$)  \ncs: ZZTOP\nallow: vendor zz-forbidden-7\npath: docs/history/*\npath: *.lock\r\n'
export RESTRICTED_WORDING_RULES="$rules"

# text <name> <want> <text> [must-not-contain]
text() {
  printf '%s\n' "$3" >"$d/in"
  bash "$script" --text "$d/in" >"$d/out" 2>&1; local rc=$?
  if [[ "$rc" -ne "$2" ]]; then no "$1 (exit $rc, want $2)"; cat "$d/out"; return; fi
  if [[ -n "${4:-}" ]] && grep -q -i -F -- "$4" "$d/out"; then no "$1 (output repeats the text)"; cat "$d/out"; return; fi
  ok "$1"
}

text "clean text passes" 0 $'fix: a bug\n\nBody text.'
text "rule hit fails, text never repeated" 1 'see zz-forbidden-42 here' 'zz-forbidden'
text "case-insensitive by default" 1 'see ZZ-Forbidden-1'
text "second rule with boundaries" 1 'a qq blocked thing'
text "boundary keeps a longer word" 0 'a qq blockedness thing'
text "case-sensitive rule hits" 1 'ZZTOP'
text "case-sensitive rule ignores other case" 0 'zztop'
text "allowed phrase passes" 0 'the Vendor ZZ-forbidden-7 product'
text "allowed phrase does not hide another hit" 1 'vendor zz-forbidden-7 and zz-forbidden-8'
text "input is data" 0 $'$(touch /nonexistent/x); `id`; -e foo'
text "empty file passes" 0 ''
printf 'zz-forbidden-3\n' >"$d/in"
bash "$script" --text "$d/in" >"$d/out" 2>&1
if grep -q -F 'in:1' "$d/out" && ! grep -q -F '[0-9]' "$d/out"; then ok "output is file:line, never the rule"; else no "output shape"; cat "$d/out"; fi

# Several files: every one is checked.
printf 'fine\n' >"$d/a"; printf 'zz-forbidden-5\n' >"$d/b"
if bash "$script" --text "$d/a" "$d/b" >/dev/null 2>&1; then no "second file ignored"; else ok "every file checked"; fi

# No rules: skipped with a notice, never a failure.
skip() {
  local out rc=0
  out="$(RESTRICTED_WORDING_RULES="$2" bash "$script" --text "$d/b" 2>&1)" || rc=$?
  if [[ "$rc" -eq 0 && "$out" == *skipped* ]]; then ok "$1"; else no "$1 (exit $rc)"; echo "$out"; fi
}
skip "unset rules: skipped" ""
skip "blank rules: skipped, not match-all" $'\n  \n# only a comment\n'
skip "only exceptions: skipped" $'allow: x\npath: y'

# --diff, --staged and --tree on a throwaway repository.
r="$d/repo"; mkdir -p "$r"; git -C "$r" init -q -b main
git -C "$r" config user.name t; git -C "$r" config user.email t@example.invalid
mkdir -p "$r/docs/history" "$r/src"
printf '%s\n' 'old line: zz-forbidden-1' >"$r/src/old.md"
printf '%s\n' 'history: zz-forbidden-2' >"$r/docs/history/notes.md"
git -C "$r" add -A; git -C "$r" commit -q -m base
base="$(git -C "$r" rev-parse HEAD)"

run() { (cd "$r" && bash "$script" "$@") >"$d/out" 2>&1; }

printf '%s\n' 'old line: zz-forbidden-1' 'new line: fine' >"$r/src/old.md"
git -C "$r" add -A
if run --staged; then ok "staged: a clean added line passes next to an old line"; else no "staged clean line"; cat "$d/out"; fi
git -C "$r" commit -q -m clean-line
if run --diff "$base" HEAD; then ok "diff: only added lines are checked"; else no "diff clean line"; cat "$d/out"; fi

printf '%s\n' 'one' 'two' 'this is zz-forbidden-9' >"$r/src/new.md"
git -C "$r" add -A
if run --staged; then no "staged: seeded line not refused"; else
  if grep -q 'src/new.md:3' "$d/out"; then ok "staged: seeded line refused with file:line"; else no "staged: wrong location"; cat "$d/out"; fi
fi
git -C "$r" commit -q -m seeded
if run --diff "$base" HEAD; then no "diff: seeded line not refused"; else ok "diff: seeded line refused"; fi
head="$(git -C "$r" rev-parse HEAD)"

printf '%s\n' 'more history: zz-forbidden-4' >>"$r/docs/history/notes.md"
printf '%s\n' 'zz-forbidden-6 1.0' >"$r/deps.lock"
git -C "$r" rm -q src/new.md
git -C "$r" add -A; git -C "$r" commit -q -m history
if run --diff "$head" HEAD; then ok "diff: excepted paths are skipped"; else no "diff: excepted path"; cat "$d/out"; fi

if run --tree; then no "tree: old line not found"; else
  if grep -q 'src/old.md:1' "$d/out" && ! grep -q 'history' "$d/out" && ! grep -q 'deps.lock' "$d/out"; then
    ok "tree: finds the old line, skips excepted paths"; else no "tree: wrong hits"; cat "$d/out"; fi
fi
printf '%s\n' 'new line: fine' >"$r/src/old.md"
git -C "$r" add -A; git -C "$r" commit -q -m clean
if run --tree; then ok "tree: clean tree passes"; else no "tree: clean tree"; cat "$d/out"; fi

# Usage errors are exit 2, never a pass.
bash "$script" >/dev/null 2>&1; [[ $? -eq 2 ]] && ok "no mode: usage" || no "no mode"
bash "$script" --diff only-one >/dev/null 2>&1; [[ $? -eq 2 ]] && ok "bad arguments: usage" || no "bad arguments"
bash "$script" --nope >/dev/null 2>&1; [[ $? -eq 2 ]] && ok "unknown mode: usage" || no "unknown mode"

echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
