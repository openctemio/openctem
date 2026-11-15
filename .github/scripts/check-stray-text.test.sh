#!/usr/bin/env bash
# Tests for check-stray-text.sh. Run: bash .github/scripts/check-stray-text.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-stray-text.sh"
pass=0 failed=0
repo() { local d; d="$(mktemp -d)"; git -C "$d" init -q -b main; echo "$d"; }
put() { mkdir -p "$(dirname "$1/$2")"; printf '%s\n' "$3" > "$1/$2"; git -C "$1" add -A; }
allow() { printf '%s\n' "$2" > "$1.allow"; }
expect() { # name want repo [needle]
  local out rc=0
  out="$(cd "$3" && STRAY_TEXT_ALLOW="$3.allow" bash "$script" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$2" ]] || [[ -n "${4:-}" && "$out" != *"$4"* ]]; then
    echo "FAIL: $1 (exit $rc, want $2)"; echo "$out"; failed=$((failed + 1))
  else echo "ok:   $1"; pass=$((pass + 1)); fi
}
# Hit strings are built from parts so this file does not trip the check itself.
lt='<' h='/hom'
h="${h}e"
d="$(repo)"; put "$d" docs/a.md 'plain text'
expect "clean tree passes" 0 "$d"
for m in "${lt}invoke name=\"Bash\">" "${lt}/invoke>" "${lt}parameter name=\"command\">" "${lt}/content>" \
  "/home/""someone/x" "see /home/""a_b-1/src" "/Users/""Someone/x" "cd /tm""p/work/repo"; do
  d="$(repo)"; put "$d" docs/a.md $'ok\n'"$m"
  expect "fails: $m" 1 "$d" "docs/a.md:2"
done
d="$(repo)"; put "$d" docs/a.md $'docker run -v /tm''p/out:/out\nls /home /Users /tm''p\nuse /hom''e/ dirs'
expect "generic /tmp use, bare dirs and prose pass" 0 "$d"
d="$(repo)"; put "$d" src/a.go "p := \"$h/x/a.go\""; allow "$d" $'# c\nsrc/a.go|/home/'
expect "allowlisted line passes" 0 "$d"
d="$(repo)"; put "$d" src/a.go "p := \"$h/x/a.go\""$'\n'"q := \"$h/y/b.go\""; allow "$d" 'src/a.go|/home/x/'
expect "allowlist is per line, other line fails" 1 "$d" "src/a.go:2"
d="$(repo)"; put "$d" src/b.go "p := \"$h/x/a.go\""; allow "$d" 'src/a.go|/home/'
expect "allowlist is per path" 1 "$d" "src/b.go:1"
echo "$pass passed, $failed failed"; [[ "$failed" -eq 0 ]]
