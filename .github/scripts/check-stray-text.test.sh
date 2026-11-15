#!/usr/bin/env bash
# Tests for check-stray-text.sh. Run: bash .github/scripts/check-stray-text.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/check-stray-text.sh"
pass=0 failed=0
repo() { local d; d="$(mktemp -d)"; git -C "$d" init -q -b main; echo "$d"; }
put() { mkdir -p "$(dirname "$1/$2")"; printf '%s\n' "$3" > "$1/$2"; git -C "$1" add -A; }
expect() { # name want repo [needle]
  local out rc=0
  out="$(cd "$3" && STRAY_TEXT_ALLOW="$3.allow" bash "$script" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$2" ]] || [[ -n "${4:-}" && "$out" != *"$4"* ]]; then
    echo "FAIL: $1 (exit $rc, want $2)"; echo "$out"; failed=$((failed + 1))
  else echo "ok:   $1"; pass=$((pass + 1)); fi
}
# Markers are built from parts so this file does not trip the check itself.
lt='<'
d="$(repo)"; put "$d" docs/a.md 'plain text'
expect "clean tree passes" 0 "$d"
for m in "${lt}invoke name=\"Bash\">" "${lt}/invoke>" "${lt}parameter name=\"command\">" "${lt}/content>" \
  "function_calls" "tool_use" "antml" "/home/""ubuntu/x" "agent-""ops/work" "/tmp/""claude-1" "scratch""pad/" \
  "workspaces"".tsv" "HAND""OFF.md"; do
  d="$(repo)"; put "$d" docs/a.md $'ok\n'"$m"
  expect "marker fails: $m" 1 "$d" "docs/a.md:2"
done
d="$(repo)"; put "$d" src/a.go 'x := "tool_""use"'; printf "%s\n" 'unrelated|zzz' > "$d.allow"
expect "split literal passes" 0 "$d"
d="$(repo)"; put "$d" src/a.go 're := `<\|tool_use\|>`'; printf "%s\n" $'# c\nsrc/a.go|tool_use' > "$d.allow"
expect "allowlisted line passes" 0 "$d"
d="$(repo)"; put "$d" src/a.go $'re := `<\\|tool_use\\|>`\nother tool_use'; printf "%s\n" 'src/a.go|`<\|tool_use' > "$d.allow"
expect "allowlist is per line, other line fails" 1 "$d" "src/a.go:2"
d="$(repo)"; put "$d" src/b.go 'tool_use'; printf "%s\n" 'src/a.go|tool_use' > "$d.allow"
expect "allowlist is per path" 1 "$d" "src/b.go:1"
echo "$pass passed, $failed failed"; [[ "$failed" -eq 0 ]]
