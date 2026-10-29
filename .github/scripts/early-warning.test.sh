#!/usr/bin/env bash
# Tests for early-warning.sh with a fake `gh` that keeps one issue in a file.
# Run: bash .github/scripts/early-warning.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/early-warning.sh"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
pass=0 failed=0
mkdir -p "$tmp/bin"
# State: $tmp/issue.json {number,title,body,open} when an issue exists; $tmp/log has every write.
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
args="$*"
case "$args" in
  "label create"*) exit 0 ;;
  *"code-scanning/alerts?ref=refs/heads/develop"*) cat "$DEV_FILE" ;;
  *"code-scanning/alerts?ref=refs/heads/main"*) cat "$MAIN_FILE" ;;
  "issue list"*) if [[ -f "$ST/issue.json" ]] && [[ "$(jq -r .open "$ST/issue.json")" == true ]]; then jq -c '[{number, title}]' "$ST/issue.json"; else echo '[]'; fi ;;
  "issue view"*) jq -r .body "$ST/issue.json" ;;
  "issue create"*)
    title="" body=""; set -- "$@"
    while [[ $# -gt 0 ]]; do case "$1" in --title) title="$2"; shift ;; --body) body="$2"; shift ;; esac; shift; done
    jq -n --arg t "$title" --arg b "$body" '{number: 1, title: $t, body: $b, open: true}' >"$ST/issue.json"; echo "create" >>"$ST/log" ;;
  "issue edit"*)
    body=""; set -- "$@"; while [[ $# -gt 0 ]]; do case "$1" in --body) body="$2"; shift ;; esac; shift; done
    jq --arg b "$body" '.body = $b' "$ST/issue.json" >"$ST/i2" && mv "$ST/i2" "$ST/issue.json"; echo "edit" >>"$ST/log" ;;
  "issue comment"*) echo "comment: $args" >>"$ST/log" ;;
  "issue close"*) jq '.open = false' "$ST/issue.json" >"$ST/i2" && mv "$ST/i2" "$ST/issue.json"; echo "close" >>"$ST/log" ;;
  *) echo "unexpected gh: $args" >&2; exit 2 ;;
esac
GH
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" ST="$tmp" DEV_FILE="$tmp/dev.json" MAIN_FILE="$tmp/main.json" REPO=o/r SHA=abcdef0123456789

alert() { echo "{\"number\":$1,\"html_url\":\"https://example.invalid/$1\",\"rule\":{\"id\":\"go/x$1\",\"security_severity_level\":\"$2\"},\"most_recent_instance\":{\"location\":{\"path\":\"a.go\",\"start_line\":3}}}"; }
arr() { local IFS=,; echo "[$*]"; }
check() { # check <name> <condition result 0/1>
  if [[ "$2" == 0 ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1"; failed=$((failed + 1)); fi
}
logged() { grep -c "^$1" "$tmp/log" 2>/dev/null || true; }
run_code() { bash "$script" code >/dev/null 2>"$tmp/err" || { cat "$tmp/err"; return 1; }; }

: >"$tmp/log"; echo '[]' >"$tmp/main.json"
arr "$(alert 1 medium)" "$(alert 2 low)" >"$tmp/dev.json"
run_code
check "medium and low alerts open nothing" "$([[ ! -f "$tmp/issue.json" ]] && echo 0 || echo 1)"

arr "$(alert 1 high)" "$(alert 2 critical)" >"$tmp/dev.json"
run_code
check "high and critical alerts open an issue" "$([[ "$(logged create)" == 1 ]] && echo 0 || echo 1)"
check "the issue lists both and marks them new" "$(jq -e '.body | contains("go/x1") and contains("go/x2") and contains("new")' "$tmp/issue.json" >/dev/null && echo 0 || echo 1)"
check "the issue records the alert numbers" "$(jq -e '.body | contains("<!-- early-warning: [\"1\",\"2\"] -->")' "$tmp/issue.json" >/dev/null && echo 0 || echo 1)"

run_code
check "an unchanged scan does not touch the issue" "$([[ "$(logged edit)" == 0 && "$(logged create)" == 1 ]] && echo 0 || echo 1)"

arr "$(alert 1 high)" "$(alert 2 critical)" "$(alert 3 high)" >"$tmp/dev.json"
run_code
check "a new alert updates the issue and is named in a comment" "$([[ "$(logged edit)" == 1 && "$(grep -c 'comment: .*3' "$tmp/log")" -ge 1 ]] && echo 0 || echo 1)"

arr "$(alert 1 high)" "$(alert 2 critical)" "$(alert 3 high)" >"$tmp/dev.json"
arr "$(alert 1 high)" >"$tmp/main.json"
run_code
check "an alert main already has is not listed" "$(jq -e '.body | contains("go/x1") | not' "$tmp/issue.json" >/dev/null && echo 0 || echo 1)"

echo '[]' >"$tmp/dev.json"
run_code
check "nothing left closes the issue" "$([[ "$(logged close)" == 1 ]] && echo 0 || echo 1)"
run_code
check "a clean scan with no issue does nothing" "$([[ "$(logged close)" == 1 && "$(logged create)" == 1 ]] && echo 0 || echo 1)"

# Images.
rm -f "$tmp/issue.json"; : >"$tmp/log"
echo '{"component":"openctem-api","target":"alpine","pkg":"libssl3","installed":"3.0.1","fixed":"3.0.2","id":"CVE-1","severity":"HIGH","kind":"os"}' >"$tmp/rep1.ndjson"
echo '{"component":"openctem-web","target":"node","pkg":"x","installed":"1","fixed":"","id":"CVE-2","severity":"CRITICAL","kind":"library"}' >>"$tmp/rep1.ndjson"
echo '{"component":"openctem-web","target":"node","pkg":"y","installed":"1","fixed":"2","id":"CVE-3","severity":"LOW","kind":"library"}' >>"$tmp/rep1.ndjson"
bash "$script" images "$tmp/rep1.ndjson" >/dev/null
check "a fixable HIGH image advisory opens an issue" "$([[ "$(logged create)" == 1 ]] && echo 0 || echo 1)"
check "unfixed and low advisories are left out" "$(jq -e '.body | contains("CVE-1") and (contains("CVE-2") | not) and (contains("CVE-3") | not)' "$tmp/issue.json" >/dev/null && echo 0 || echo 1)"
: >"$tmp/empty.ndjson"
bash "$script" images "$tmp/empty.ndjson" >/dev/null
check "no advisories closes it" "$([[ "$(logged close)" == 1 ]] && echo 0 || echo 1)"

echo "$pass passed, $failed failed"
(( failed == 0 ))
