#!/usr/bin/env bash
# Tests the two optional inputs of go-shard.sh (affected list, recorded
# durations): every selected package still lands on exactly one shard, a
# package outside the list never runs, and the durations balance the shards.
# Run from api/.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
all="$tmp/all"
go list ./... | LC_ALL=C sort > "$all"
export GO_SHARD_SKIP_COMPILED=1 # compiling every package is `check`'s own job in CI
shard() { bash "$here/go-shard.sh" "$@"; }

# 1. A subset (every 4th package, plus one SPLIT package) and a durations file
#    that makes one package dominate, plus junk entries.
awk 'NR % 4 == 0' "$all" > "$tmp/affected"
echo "github.com/openctemio/openctem/api/tests/unit" >> "$tmp/affected"
{
  echo '{'
  awk 'NR % 3 == 0 { printf "\"%s\": %d,\n", $0, NR }' "$all"
  echo '"not/a/package": 99999, "x": "text", "y": -5, "z": null }'
} > "$tmp/durations.json"
GO_SHARD_AFFECTED="$tmp/affected" GO_SHARD_DURATIONS="$tmp/durations.json" shard check 1 2 5 8 >/dev/null
GO_SHARD_AFFECTED="$tmp/affected" shard check 3 6 >/dev/null
GO_SHARD_DURATIONS="$tmp/durations.json" shard check 3 6 8 >/dev/null
echo "ok: subset and durations cover each selected package once"

# 2. An empty selection runs nothing at all.
: > "$tmp/none"
out="$(GO_SHARD_AFFECTED="$tmp/none" shard plan 0 3)"
[ -z "$out" ] || { echo "FAIL: an empty selection planned: $out" >&2; exit 1; }
echo "ok: empty selection plans nothing"

# 3. A package outside the list is on no shard.
out="$(for i in 0 1 2; do GO_SHARD_AFFECTED="$tmp/affected" shard plan "$i" 3; done)"
if grep -q 'tests/integration' <<<"$out"; then echo "FAIL: tests/integration ran outside the selection" >&2; exit 1; fi
echo "ok: unselected SPLIT package is skipped"

# 4. With durations the heaviest package sits alone on a shard when it alone
#    outweighs the rest.
{
  printf '{'; awk 'NR > 1 { printf "\"%s\": 1,", $0 }' "$all"; printf '"%s": 100000}\n' "$(head -1 "$all")"
} > "$tmp/heavy.json"
heavy="$(head -1 "$all")"
for i in 0 1 2 3; do
  l="$(GO_SHARD_DURATIONS="$tmp/heavy.json" shard plan "$i" 4 | grep '^pkgs ' | tr ' ' '\n' | grep -c '^github' || true)"
  if GO_SHARD_DURATIONS="$tmp/heavy.json" shard plan "$i" 4 | grep -q "^pkgs.* $heavy\( \|$\)"; then
    [ "$l" = 1 ] || { echo "FAIL: shard $i holds the heavy package and $((l - 1)) others" >&2; exit 1; }
    echo "ok: heavy package is alone on shard $i"
  fi
done
echo "go-shard: all passed"
