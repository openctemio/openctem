#!/usr/bin/env bash
# Tests the "Decide who must sign" step of .github/workflows/cla.yml against
# recorded commit lists. Run: bash .github/scripts/cla-scope.test.sh
# Needs bash, jq and python3. The step's script is extracted from the workflow,
# so the test always exercises the committed logic.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
wf="$root/.github/workflows/cla.yml"
tmp=$(mktemp -d)
trap 'find "$tmp" -delete' EXIT

python3 -I - "$wf" "$tmp/scope.sh" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
step = s[s.index("id: scope"):]
m = re.search(r"\n        run: \|\n((?:          .*\n|\n)+)", step)
open(sys.argv[2], "w").write("".join(l[10:] + "\n" for l in m.group(1).splitlines()))
PY
allowlist=$(sed -n 's/^  CLA_ALLOWLIST: "\(.*\)"$/\1/p' "$wf")
[ -n "$allowlist" ] || { echo "CLA_ALLOWLIST not found in $wf"; exit 1; }

mkdir -p "$tmp/bin"
printf '#!/usr/bin/env bash\ncat "$FIXTURE"\n' > "$tmp/bin/gh"
chmod +x "$tmp/bin/gh"

commit() { # sha author committer verified
  local a=null c=null
  [ "$2" = - ] || a="{\"login\":\"$2\"}"
  [ "$3" = - ] || c="{\"login\":\"$3\"}"
  printf '{"sha":"%s","author":%s,"committer":%s,"commit":{"verification":{"verified":%s}}}' "$1" "$a" "$c" "$4"
}

fail=0
# case <name> <opener> <expected: run=true|run=false|error> <commits...>
case_() {
  local name=$1 opener=$2 want=$3; shift 3
  local list; list=$(IFS=,; echo "[$*]")
  echo "$list" > "$tmp/fixture.json"
  : > "$tmp/out"
  local got
  if FIXTURE="$tmp/fixture.json" OPENER="$opener" PR=1 REPO=o/r RUNNER_TEMP="$tmp" \
     GITHUB_OUTPUT="$tmp/out" CLA_ALLOWLIST="$allowlist" PATH="$tmp/bin:$PATH" \
     bash "$tmp/scope.sh" > "$tmp/log" 2>&1; then
    got=$(cat "$tmp/out")
  else
    got=error
  fi
  if [ "$got" = "$want" ]; then echo "ok   $name"; else echo "FAIL $name: want $want, got $got"; cat "$tmp/log"; fail=1; fi
}

case_ "maintainer PR, own unlinked commits" 0xmanhnv run=false \
  "$(commit a1 0xmanhnv 0xmanhnv false)" "$(commit a2 - - false)"
case_ "maintainer PR with an outside account's commit" 0xmanhnv run=true \
  "$(commit b1 someone someone false)"
case_ "bot PR" 'dependabot[bot]' run=false \
  "$(commit c1 'dependabot[bot]' web-flow true)"
case_ "outside PR, own commits" someone run=true \
  "$(commit d1 someone someone false)"
case_ "outside PR, unlinked commits" someone run=true \
  "$(commit d2 - - false)"
case_ "outside PR, maintainer as author, unsigned" someone error \
  "$(commit e1 0xmanhnv someone false)"
case_ "outside PR, maintainer as author, signed by the contributor" someone error \
  "$(commit e2 0xmanhnv someone true)"
case_ "outside PR, maintainer as committer only, author unlinked" someone error \
  "$(commit e3 - 0xmanhnv true)"
case_ "outside PR, maintainer as author and committer, unsigned" someone error \
  "$(commit e4 0xmanhnv 0xmanhnv false)"
case_ "outside PR, maintainer commit authored, committed and signed by the maintainer" someone run=true \
  "$(commit f1 0xmanhnv 0xmanhnv true)" "$(commit f2 someone someone false)"

exit $fail
