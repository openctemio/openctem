#!/usr/bin/env bash
# Tests for fail-fast.sh. Run: bash .github/scripts/fail-fast.test.sh
# A fake `gh` on PATH answers the runs query and records every cancel; nothing
# reaches GitHub.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/fail-fast.sh"
pass=0 failed=0
d="$(mktemp -d)"
trap 'find "$d" -delete' EXIT
sha=0123456789abcdef0123456789abcdef01234567
other=ffffffffffffffffffffffffffffffffffffffff
cat >"$d/gh" <<'GH'
#!/usr/bin/env bash
# `gh api -X POST .../runs/<id>/cancel` appends <id> to $CANCEL_LOG;
# `gh api <list> --jq <filter>` applies the filter to $FAKE_RUNS.
[ -n "${FAKE_FAIL:-}" ] && exit 1
if [ "$2" = -X ]; then
  id="${4%/cancel}"; id="${id##*/}"
  echo "$id" >>"$CANCEL_LOG"
  [ "$id" = "${FAKE_CANCEL_FAIL:-}" ] && exit 1
  exit 0
fi
[ -n "${FAKE_LIST_FAIL:-}" ] && exit 1
while [ $# -gt 0 ]; do [ "$1" = --jq ] && { shift; jq -r "$1" <<<"$FAKE_RUNS"; exit; }; shift; done
GH
chmod +x "$d/gh"

run() { # <want cancels, space separated, in order> <name> <runs json> [env...]
  local want=$1 name=$2 runs=$3 got rc=0; shift 3
  : >"$d/log"
  env PATH="$d:$PATH" CANCEL_LOG="$d/log" FAKE_RUNS="$runs" REPO=o/r EVENT=merge_group RUN_ID=100 \
    HEAD_SHA=$sha HEAD_REPO= "$@" bash "$script" >/dev/null 2>&1 || rc=$?
  got="$(tr '\n' ' ' <"$d/log" | sed 's/ $//')"
  if [ "$got" = "$want" ] && [ "$rc" = 0 ]; then echo "ok:   $name"; pass=$((pass + 1))
  else echo "FAIL: $name (want '$want' rc 0, got '$got' rc $rc)"; failed=$((failed + 1)); fi
}
r() { # <id> <sha> <event> <status>
  printf '{"id":%s,"head_sha":"%s","event":"%s","status":"%s"}' "$@"
}
runs() { local IFS=,; printf '{"workflow_runs":[%s]}' "$*"; }

all="$(runs "$(r 100 $sha merge_group in_progress)" "$(r 101 $sha merge_group in_progress)" \
  "$(r 102 $sha merge_group queued)" "$(r 103 $sha merge_group completed)" \
  "$(r 104 $other merge_group in_progress)" "$(r 105 $sha pull_request in_progress)" \
  "$(r 106 $sha push in_progress)")"

run "101 102" "merge_group: other unfinished runs of the same head, never this run" "$all"
run "101 102" "merge_group: a failed cancel does not stop the others" "$all" FAKE_CANCEL_FAIL=101
run "" "merge_group: no other runs, this run keeps its failed job" "$(runs "$(r 100 $sha merge_group in_progress)")"
run "" "merge_group: list error cancels nothing" "$all" FAKE_LIST_FAIL=1
run "" "merge_group: missing head sha" "$all" HEAD_SHA=
run "" "merge_group: malformed head sha" "$all" HEAD_SHA="$sha;x"
run "" "malformed run id" "$all" RUN_ID='1;x'
run "" "pull_request: this run keeps its failed job" "$all" EVENT=pull_request HEAD_REPO=o/r
run "" "pull_request from a fork: nothing" "$all" EVENT=pull_request HEAD_REPO=fork/r
run "" "push: nothing" "$all" EVENT=push
run "" "schedule: nothing" "$all" EVENT=schedule

# Every gh call fails (no token, network): still exit 0, no cancels recorded.
: >"$d/log"
if env PATH="$d:$PATH" CANCEL_LOG="$d/log" FAKE_FAIL=1 FAKE_RUNS="$all" REPO=o/r EVENT=merge_group \
  RUN_ID=100 HEAD_SHA=$sha bash "$script" >/dev/null 2>&1 && [ ! -s "$d/log" ]; then
  echo "ok:   gh unavailable: warning only"; pass=$((pass + 1))
else echo "FAIL: gh unavailable: warning only"; failed=$((failed + 1)); fi

echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
