#!/usr/bin/env bash
# Tests for codeql-new-alerts.sh. Run: bash .github/scripts/codeql-new-alerts.test.sh
# Stubs `gh` on PATH; touches nothing else.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/codeql-new-alerts.sh"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
pass=0 failed=0

cat >"$tmp/gh" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *"ref=refs/pull/7/merge"*) cat "$PR_FILE" ;;
  *"ref=refs/heads/develop"*) cat "$BASE_FILE" ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
STUB
chmod +x "$tmp/gh"

alert() { # alert <number> <severity|null> [rule]
  local sev="$2"; [[ "$sev" != null ]] && sev="\"$sev\""
  echo "{\"number\":$1,\"html_url\":\"https://example.invalid/$1\",\"rule\":{\"id\":\"${3:-go/x}\",\"security_severity_level\":$sev},\"most_recent_instance\":{\"location\":{\"path\":\"a.go\",\"start_line\":3}}}"
}
arr() { local IFS=,; echo "[$*]"; }

expect() { # expect <name> <rc> <needle> <pr json> <base json>
  local out rc=0
  echo "$4" >"$tmp/pr.json"; echo "$5" >"$tmp/base.json"
  out="$(PATH="$tmp:$PATH" PR_FILE="$tmp/pr.json" BASE_FILE="$tmp/base.json" \
    REPO=o/r PR_NUMBER=7 BASE_REF=develop GITHUB_STEP_SUMMARY="$tmp/sum" bash "$script" 2>&1)" || rc=$?
  if [[ "$rc" -ne "$2" ]] || [[ -n "$3" && "$out" != *"$3"* ]]; then
    echo "FAIL: $1 (exit $rc, want $2)"; echo "$out"; failed=$((failed + 1))
  else
    echo "ok:   $1"; pass=$((pass + 1))
  fi
}

expect "no alerts anywhere passes" 0 "No new" "[]" "[]"
expect "alert already on base passes" 0 "No new" "$(arr "$(alert 1 high)")" "$(arr "$(alert 1 high)")"
expect "new high alert fails and is listed" 1 "go/new" "$(arr "$(alert 1 high)" "$(alert 2 high go/new)")" "$(arr "$(alert 1 high)")"
expect "new medium alert fails" 1 "| medium |" "$(arr "$(alert 2 medium)")" "[]"
expect "new critical alert fails" 1 "| critical |" "$(arr "$(alert 2 critical)")" "[]"
expect "new low alert passes" 0 "No new" "$(arr "$(alert 2 low)")" "[]"
expect "new quality alert without security severity passes" 0 "No new" "$(arr "$(alert 2 null)")" "[]"
expect "alert fixed by the PR passes" 0 "No new" "[]" "$(arr "$(alert 1 high)")"
echo "$pass passed, $failed failed"
[[ "$failed" -eq 0 ]]
