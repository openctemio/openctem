#!/usr/bin/env bash
# Tests for green-base.sh with a fake `gh`. Run: bash .github/scripts/green-base.test.sh
set -euo pipefail
script="$(cd "$(dirname "$0")" && pwd)/green-base.sh"
pass=0 failed=0
d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
mkdir -p "$d/bin" "$d/data"
# Fake gh: pulls/N/commits -> data/commits (one sha per line);
# commits/SHA/check-runs -> data/SHA.json (array of check runs) as the --jq output.
cat >"$d/bin/gh" <<'GH'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    *pulls/*/commits*) cat "$FAKE/commits"; exit 0 ;;
    *commits/*/check-runs*) sha="${a#*commits/}"; sha="${sha%%/*}"
      [[ -f "$FAKE/$sha.json" ]] || exit 1
      jq -c '.[]' "$FAKE/$sha.json"; exit 0 ;;
  esac
done
exit 1
GH
chmod +x "$d/bin/gh"
export FAKE="$d/data" PATH="$d/bin:$PATH" REPO=o/r PR_NUMBER=7 PR_HEAD_SHA=ccc
export INCREMENTAL_CHECKS="API CI OK,Web CI OK"

run() { # name conclusion app
  printf '{"name":"%s","status":"completed","conclusion":"%s","app":"%s"}' "$1" "$2" "${3:-github-actions}"
}
expect() { # name want
  local got; got="$(bash "$script" 2>/dev/null)"
  if [[ "$got" == "$2" ]]; then echo "ok:   $1"; pass=$((pass + 1)); else echo "FAIL: $1 (want '$2', got '$got')"; failed=$((failed + 1)); fi
}

printf 'aaa\nbbb\nccc\n' >"$FAKE/commits"
echo "[$(run 'API CI OK' success),$(run 'Web CI OK' skipped)]" >"$FAKE/aaa.json"
echo "[$(run 'API CI OK' failure),$(run 'Web CI OK' success)]" >"$FAKE/bbb.json"
expect "newest green before the head, skipping a red one" aaa

echo "[$(run 'API CI OK' success),$(run 'Web CI OK' success)]" >"$FAKE/bbb.json"
expect "the newest green wins" bbb

echo "[$(run 'API CI OK' success),$(run 'Web CI OK' success)]" >"$FAKE/ccc.json"
expect "the head itself is never the base" bbb

echo "[$(run 'API CI OK' success)]" >"$FAKE/bbb.json"
expect "a required check that never ran is red" aaa

echo "[$(run 'API CI OK' success),$(run 'Web CI OK' success 'some-other-app')]" >"$FAKE/bbb.json"
expect "a check from another app does not count" aaa

echo '[{"name":"API CI OK","status":"in_progress","conclusion":null,"app":"github-actions"},'"$(run 'Web CI OK' success)]" >"$FAKE/bbb.json"
expect "a pending check is red" aaa

echo "[$(run 'API CI OK' cancelled),$(run 'Web CI OK' success)]" >"$FAKE/aaa.json"
expect "no green commit prints nothing" ""

echo "[$(run 'API CI OK' success),$(run 'Web CI OK' success)]" >"$FAKE/aaa.json"
rm "$FAKE/bbb.json"
expect "a commit whose checks cannot be read is skipped" aaa

echo "$pass passed, $failed failed"
(( failed == 0 ))
