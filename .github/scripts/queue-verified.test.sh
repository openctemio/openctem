#!/usr/bin/env bash
# Tests for queue-verified.sh. Run: bash .github/scripts/queue-verified.test.sh
# A fake `gh` on PATH answers the runs query; nothing reaches GitHub.
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/queue-verified.sh"
pass=0 failed=0
d="$(mktemp -d)"
sha=0123456789abcdef0123456789abcdef01234567
cat >"$d/gh" <<'GH'
#!/usr/bin/env bash
# Applies the caller's --jq filter to $FAKE_RUNS, like `gh api --jq`.
[ -n "${FAKE_FAIL:-}" ] && exit 1
while [ $# -gt 0 ]; do [ "$1" = --jq ] && { shift; jq -r "$1" <<<"$FAKE_RUNS"; exit; }; shift; done
GH
chmod +x "$d/gh"

run() { # <expect> <name> <runs json> [env...]
  local want=$1 name=$2 runs=$3 got; shift 3
  got="$(env PATH="$d:$PATH" FAKE_RUNS="$runs" EVENT=push REF=refs/heads/develop SHA=$sha REPO=o/r \
    WORKFLOW_REF="o/r/.github/workflows/api-ci.yml@refs/heads/develop" GITHUB_OUTPUT= "$@" bash "$script" 2>/dev/null)"
  if [ "$got" = "verified=$want" ]; then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (want $want, got $got)"; failed=$((failed + 1)); fi
}
mk() { # <event> <path> <sha> <conclusion>
  printf '{"workflow_runs":[{"event":"%s","path":"%s","head_sha":"%s","conclusion":"%s"}]}' "$@"
}
ok_run="$(mk merge_group .github/workflows/api-ci.yml $sha success)"

run true "queue passed this workflow on this sha" "$ok_run"
run false "another workflow passed" "$(mk merge_group .github/workflows/web-ci.yml $sha success)"
run false "a pull_request run does not count" "$(mk pull_request .github/workflows/api-ci.yml $sha success)"
run false "another sha does not count" "$(mk merge_group .github/workflows/api-ci.yml ffffffffffffffffffffffffffffffffffffffff success)"
run false "a failed queue run does not count" "$(mk merge_group .github/workflows/api-ci.yml $sha failure)"
run false "no runs" '{"workflow_runs":[]}'
run false "api error runs everything" "$ok_run" FAKE_FAIL=1
run false "pull_request event" "$ok_run" EVENT=pull_request
run false "merge_group event" "$ok_run" EVENT=merge_group
run false "push to main" "$ok_run" REF=refs/heads/main
run false "malformed sha" "$ok_run" SHA='abc;rm'
run false "workflow outside .github/workflows" "$ok_run" WORKFLOW_REF="o/r/x/api-ci.yml@refs/heads/develop"

find "$d" -mindepth 1 -delete; rmdir "$d"
echo "$pass passed, $failed failed"
[ "$failed" = 0 ]
