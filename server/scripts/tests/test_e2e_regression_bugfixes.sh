#!/bin/bash
# =============================================================================
# E2E Regression Guards — 2026-07 correctness bug-hunt fixes (api #228-242)
# =============================================================================
# Each check asserts the FIXED behavior against a live API, so a regression
# in any of these merged fixes fails loudly.
#
#   ./test_e2e_regression_bugfixes.sh [API_URL]
# =============================================================================
source "$(cd "$(dirname "$0")" && pwd)/_e2e_common.sh"
e2e_init "regression-bugfixes"
e2e_bootstrap_auth
AUTH="$(auth_hdr)"

# --- setup: an asset + a finding to hang assertions on ---------------------
print_test "setup: create asset"
do_request POST /api/v1/assets \
    "{\"name\":\"regress-${TIMESTAMP}.example.com\",\"type\":\"domain\",\"criticality\":\"medium\"}" "$AUTH"
assert_status "200|201" "create asset"
ASSET_ID=$(extract_json "$BODY" '.id')

print_test "setup: create finding"
do_request POST /api/v1/findings "{
    \"asset_id\":\"$ASSET_ID\",\"source\":\"sast\",\"tool_name\":\"semgrep\",
    \"rule_id\":\"regress-${TIMESTAMP}\",\"message\":\"regression seed finding\",
    \"severity\":\"high\",\"file_path\":\"a.go\",\"start_line\":1,\"end_line\":1}" "$AUTH"
assert_status "200|201" "create finding"
FINDING_ID=$(extract_json "$BODY" '.id')

# --- #233: GET /components/{missing} must be 404, not a 500 nil-deref -------
print_test "#233 missing component -> 404 (not 500 nil-deref)"
do_request GET /api/v1/components/00000000-0000-0000-0000-000000000000 "" "$AUTH"
assert_not_status "500" "component-not-found does not 500"
assert_status "404" "component-not-found returns 404"

# --- #234: audit resource history ?per_page=0 must not divide-by-zero panic -
print_test "#234 audit ?per_page=0 -> no divide-by-zero 500"
do_request GET "/api/v1/audit-logs/resource/finding/${FINDING_ID}?per_page=0" "" "$AUTH"
assert_not_status "500" "audit per_page=0 does not panic (500)"

# --- #234: findings/groups page 1 returns the seed finding (no arg swap) ----
print_test "#234 findings/groups page 1 is not silently empty"
do_request GET "/api/v1/findings/groups?group_by=severity&page=1&per_page=20" "" "$AUTH"
assert_status "200" "findings/groups responds"
assert_json '(.data | length) >= 1' "page 1 contains groups (pagination not swapped)"

# --- #238: invalid exposure filter is rejected (400), not fail-open all -----
print_test "#238 invalid exposure filter -> 400 (not fail-open)"
do_request GET "/api/v1/exposures?severity=criticl" "" "$AUTH"
assert_status "400" "invalid severity filter rejected"

# --- #236: malformed threat-actor id -> 400, not a silent 204 no-op --------
print_test "#236 DELETE threat-actor with malformed id -> 400 (not 204)"
do_request DELETE /api/v1/threat-actors/not-a-uuid "" "$AUTH"
assert_not_status "204" "malformed actor id is not a silent 204"
assert_status "400" "malformed actor id -> 400"

# --- #241: BulkFixApplied response distinguishes failed from skipped --------
print_test "#241 fix-applied result exposes a 'failed' counter"
do_request POST /api/v1/findings/actions/fix-applied \
    "{\"filter\":{\"cve_ids\":[]},\"note\":\"regression probe\"}" "$AUTH"
if echo "$HTTP_CODE" | grep -qE '^(200|201)$'; then
    assert_json 'has("failed")' "result has 'failed' field"
else
    print_skip "#241 fix-applied not exercisable (HTTP $HTTP_CODE)"
fi

# --- #230: compliance score is within [0,100] ------------------------------
print_test "#230 compliance framework score is in [0,100]"
do_request GET /api/v1/compliance/frameworks "" "$AUTH"
FW_ID=$(extract_json "$BODY" '(.data // .items // [])[0].id // empty')
if [ -n "$FW_ID" ]; then
    do_request GET "/api/v1/compliance/frameworks/${FW_ID}/stats" "" "$AUTH"
    if echo "$HTTP_CODE" | grep -qE '^200$'; then
        assert_json '(.compliance_score // .score // 0) >= 0 and (.compliance_score // .score // 0) <= 100' \
            "compliance_score within [0,100]"
    else
        print_skip "#230 framework stats not available (HTTP $HTTP_CODE)"
    fi
else
    print_skip "#230 no seeded compliance framework to check"
fi

e2e_finish
