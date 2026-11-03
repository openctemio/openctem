#!/usr/bin/env bash
# Tests for check-attribution.sh. Run: bash .github/scripts/check-attribution.test.sh
set -u
script="$(cd "$(dirname "$0")" && pwd)/check-attribution.sh"
d="$(mktemp -d)"; trap 'find "$d" -delete' EXIT
pass=0 failed=0
expect() { # name want text
  printf '%s\n' "$3" >"$d/in"
  bash "$script" "$d/in" >/dev/null 2>&1; local rc=$?
  if [[ "$rc" -eq "$2" ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1 (exit $rc, want $2)"; failed=$((failed + 1)); fi
}
expect clean 0 $'fix: a bug\n\nBody text.'
expect coauthor-claude 1 $'fix\n\nCo-Authored-By: Claude Sonnet <noreply@anthropic.com>'
expect coauthor-lowercase 1 'co-authored-by: someone (Anthropic)'
expect coauthor-human 0 'Co-authored-by: Alice <alice@example.org>'
expect session-trailer 1 'Claude-Session: https://example.org/x'
expect session-link 1 'see https://claude.ai/code/session_abc'
expect generated-link 1 '🤖 Generated with [Claude Code](https://claude.com/claude-code)'
expect generated-plain 1 'Generated with Claude Code'
expect generated-other 0 'Generated with protoc'
expect injection-text-is-data 0 $'$(touch /nonexistent/x); `id`; -e foo'
# A missing file must not pass silently as a match, and several files are all checked.
printf 'ok\n' >"$d/a"; printf 'Claude-Session: x\n' >"$d/b"
if bash "$script" "$d/a" "$d/b" >/dev/null 2>&1; then echo "FAIL: second file ignored"; failed=$((failed + 1)); else echo "ok:   every file checked"; pass=$((pass + 1)); fi
echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
