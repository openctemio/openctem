#!/bin/bash
# Runs every E2E flow script, captures PASS/FAIL, and appends a machine-readable
# line per flow to $RESULTS so progress survives interruption/context loss.
# Delay between scripts respects the auth registration rate limit (3/min).
#
#   ./run_status.sh [API_URL] [DELAY_SECONDS]
API_URL="${1:-${API_URL:-http://localhost:8080}}"
DELAY="${2:-25}"
DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${RESULTS:-$DIR/.e2e_results.tsv}"
export API_URL

: > "$RESULTS"
SCRIPTS=$(ls "$DIR"/test_e2e_*.sh "$DIR"/test_full_flow.sh 2>/dev/null | sort)
i=0
for s in $SCRIPTS; do
    name=$(basename "$s")
    i=$((i+1))
    [ "$i" -gt 1 ] && sleep "$DELAY"
    out=$(bash "$s" "$API_URL" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    # Summary formats vary: "PASSED: N ... FAILED: N" and "Passed: N / Failed: N".
    # A number MUST follow the keyword (per-test lines have text, not a count),
    # so this only matches the final summary line(s); take the last.
    p=$(echo "$out" | grep -ioE "passed:? *[0-9]+" | grep -oE "[0-9]+" | tail -1)
    f=$(echo "$out" | grep -ioE "failed:? *[0-9]+" | grep -oE "[0-9]+" | tail -1)
    p=${p:-?}; f=${f:-?}
    # no parsable summary => the script/setup broke before finishing
    if [ "$f" = "?" ] && [ "$p" = "?" ]; then status="ERROR"
    elif [ "$f" = "0" ] || { [ "$f" = "?" ] && [ "$p" != "?" ]; }; then status="PASS"
    else status="FAIL"; fi
    printf '%s\t%s\t%s\t%s\n' "$name" "$status" "P=$p" "F=$f" >> "$RESULTS"
    echo "[$i] $name -> $status (P=$p F=$f)"
    # capture first few failure lines for triage
    echo "$out" | grep -iE "FAIL(ED)?:" | head -8 | sed "s/^/[$name] /" >> "$RESULTS.fails"
done
echo "DONE -> $RESULTS"
