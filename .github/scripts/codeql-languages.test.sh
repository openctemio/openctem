#!/usr/bin/env bash
# Tests for codeql-languages.sh. Run: bash .github/scripts/codeql-languages.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/codeql-languages.sh"
pass=0 failed=0
both='["go","javascript-typescript"]'
run() { # <expect> <name> [env...]
  local want=$1 name=$2 got; shift 2
  got="$(env -i PATH="$PATH" GITHUB_OUTPUT= "$@" bash "$script")"
  if [ "$got" = "languages=$want" ]; then echo "ok:   $name"; pass=$((pass + 1)); else echo "FAIL: $name (want $want, got $got)"; failed=$((failed + 1)); fi
}
run '["go"]' "PR, api only" EVENT=pull_request API=true WEB=false
run '["javascript-typescript"]' "PR, web only" EVENT=pull_request API=false WEB=true
run '[]' "PR, neither" EVENT=pull_request API=false WEB=false
run "$both" "PR, both" EVENT=pull_request API=true WEB=true
run '["go"]' "develop push, api only" EVENT=push REF=refs/heads/develop API=true WEB=false
run '["javascript-typescript"]' "develop push, web only" EVENT=push REF=refs/heads/develop API=false WEB=true
run '[]' "develop push, docs only" EVENT=push REF=refs/heads/develop API=false WEB=false
run "$both" "main push is always both" EVENT=push REF=refs/heads/main API=false WEB=false
run "$both" "schedule is always both" EVENT=schedule REF=refs/heads/main API=false WEB=false
run "$both" "dispatch is always both" EVENT=workflow_dispatch API=false WEB=false
run "$both" "missing inputs analyse both" EVENT=pull_request
run '["go"]' "unexpected value counts as changed" EVENT=push REF=refs/heads/develop API=maybe WEB=false
echo "pass=$pass failed=$failed"
[ "$failed" -eq 0 ]
