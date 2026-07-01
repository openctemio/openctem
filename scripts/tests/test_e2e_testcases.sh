#!/bin/bash
# =============================================================================
# E2E Test-Case Suite — negative / authz / IDOR / state-machine / boundary
# =============================================================================
# Implements the non-happy-path rows of E2E_TESTCASE_MAP.md against a live API.
# Uses TWO tenants (A + B) for cross-tenant isolation; single session each, so
# it stays under the auth 3/min limit (internal delay before user B).
#
#   ./test_e2e_testcases.sh [API_URL]
# =============================================================================
source "$(cd "$(dirname "$0")" && pwd)/_e2e_common.sh"
e2e_init "testcases"
e2e_bootstrap_auth        # tenant A (uses shared jar/ACCESS_TOKEN)
A="$(auth_hdr)"

section() { echo -e "\n${BLUE}──── $1 ────${NC}"; }
UUID0="00000000-0000-0000-0000-000000000000"

# ------------------------------- setup (A) ---------------------------------
print_test "setup: A creates asset + finding"
do_request POST /api/v1/assets "{\"name\":\"tc-${TIMESTAMP}.example.com\",\"type\":\"domain\",\"criticality\":\"high\"}" "$A"
assert_status "200|201" "A create asset"; ASSET_A=$(extract_json "$BODY" '.id')
do_request POST /api/v1/findings "{\"asset_id\":\"$ASSET_A\",\"source\":\"sast\",\"tool_name\":\"semgrep\",\"rule_id\":\"tc-${TIMESTAMP}\",\"message\":\"tc finding\",\"severity\":\"high\",\"file_path\":\"a.go\",\"start_line\":1,\"end_line\":1}" "$A"
assert_status "200|201" "A create finding"; FIND_A=$(extract_json "$BODY" '.id')

# =============================== VALIDATION =================================
section "VAL — validation / negative input"
print_test "ASSET-VAL-1 missing criticality"; do_request POST /api/v1/assets "{\"name\":\"x-${TIMESTAMP}\",\"type\":\"domain\"}" "$A"
assert_status "400|422" "missing criticality rejected"
print_test "ASSET-VAL-2 invalid type"; do_request POST /api/v1/assets "{\"name\":\"x-${TIMESTAMP}\",\"type\":\"bogus\",\"criticality\":\"high\"}" "$A"
assert_status "400|422" "invalid type rejected"
print_test "ASSET-VAL-3 empty name"; do_request POST /api/v1/assets "{\"name\":\"\",\"type\":\"domain\",\"criticality\":\"high\"}" "$A"
assert_status "400|422" "empty name rejected"
print_test "FIND-VAL-1 missing asset_id"; do_request POST /api/v1/findings "{\"source\":\"sast\",\"tool_name\":\"t\",\"rule_id\":\"r\",\"message\":\"m\",\"severity\":\"high\"}" "$A"
assert_status "400|422" "missing asset_id rejected"
print_test "FIND-VAL-2 invalid severity"; do_request POST /api/v1/findings "{\"asset_id\":\"$ASSET_A\",\"source\":\"sast\",\"tool_name\":\"t\",\"rule_id\":\"r\",\"message\":\"m\",\"severity\":\"ultra\"}" "$A"
assert_status "400|422" "invalid severity rejected"
print_test "EXP-VAL-2 invalid state filter"; do_request GET "/api/v1/exposures?state=bogus" "" "$A"
assert_status "400" "invalid exposure state rejected"

# ================================ NOT FOUND ================================
section "NF — not found / malformed"
print_test "ASSET-NF-1 missing asset"; do_request GET "/api/v1/assets/$UUID0" "" "$A"
assert_status "404" "missing asset 404"
print_test "ASSET-NF-2 malformed id"; do_request GET "/api/v1/assets/not-a-uuid" "" "$A"
assert_status "400|404" "malformed asset id 4xx"
print_test "FIND-NF-1 missing finding"; do_request GET "/api/v1/findings/$UUID0" "" "$A"
assert_status "404" "missing finding 404"
print_test "FIND-NF-2 patch missing finding status"; do_request PATCH "/api/v1/findings/$UUID0/status" "{\"status\":\"confirmed\"}" "$A"
assert_status "404" "patch missing finding 404"
print_test "CMPN-NF-1 missing component (#233)"; do_request GET "/api/v1/components/$UUID0" "" "$A"
assert_status "404" "missing component 404"

# ============================== AUTHN / CSRF ===============================
section "AZ — authn / CSRF"
print_test "AUTH-AZ-1 no token"; do_request GET /api/v1/assets "" ""
assert_status "401" "no token 401"
print_test "AUTH-AZ-2 garbage token"; do_request GET /api/v1/assets "" "Authorization: Bearer not.a.jwt"
assert_status "401" "garbage token 401"
print_test "AUTH-AZ-3 mutation without CSRF"
# bypass the auto-CSRF by calling curl directly (no X-CSRF-Token)
raw_csrf=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/assets" -H "Content-Type: application/json" -H "$A" -c "$COOKIE_JAR" -b "$COOKIE_JAR" -d "{\"name\":\"nocsrf-${TIMESTAMP}\",\"type\":\"domain\",\"criticality\":\"low\"}" | tail -1)
if [ "$raw_csrf" = "403" ]; then print_success "mutation without CSRF -> 403"; else print_failure "CSRF not enforced" "got $raw_csrf"; fi

# ============================ STATE MACHINE ================================
section "SM — finding status transitions"
print_test "FIND-SM-2 new→resolved (invalid skip)"; do_request PATCH "/api/v1/findings/$FIND_A/status" "{\"status\":\"resolved\"}" "$A"
assert_status "400|409|422" "invalid skip new→resolved rejected"
print_test "FIND-SM-1 new→confirmed (valid)"; do_request PATCH "/api/v1/findings/$FIND_A/status" "{\"status\":\"confirmed\"}" "$A"
assert_status "200|204" "new→confirmed ok"
print_test "FIND-SM-4 confirmed→fix_applied (invalid skip)"; do_request PATCH "/api/v1/findings/$FIND_A/status" "{\"status\":\"fix_applied\",\"note\":\"x\"}" "$A"
assert_status "400|409|422" "invalid skip confirmed→fix_applied rejected"
print_test "FIND-SM-3 confirmed→in_progress (valid)"; do_request PATCH "/api/v1/findings/$FIND_A/status" "{\"status\":\"in_progress\"}" "$A"
assert_status "200|204" "confirmed→in_progress ok"
print_test "FIND-SM-5 in_progress→fix_applied (valid, note)"; do_request PATCH "/api/v1/findings/$FIND_A/status" "{\"status\":\"fix_applied\",\"note\":\"patched in PR#1\"}" "$A"
assert_status "200|204" "in_progress→fix_applied ok"

# ============================== BOUNDARY ==================================
section "BND — pagination / limits"
print_test "FIND-BND-2 per_page=0"; do_request GET "/api/v1/findings?per_page=0" "" "$A"
assert_not_status "500" "findings per_page=0 no 500"
print_test "BND huge per_page"; do_request GET "/api/v1/findings?per_page=1000000" "" "$A"
assert_not_status "500" "findings per_page=huge no 500"
print_test "BND page=0"; do_request GET "/api/v1/findings?page=0&per_page=20" "" "$A"
assert_not_status "500" "findings page=0 no 500"
print_test "BND negative page"; do_request GET "/api/v1/findings?page=-5&per_page=20" "" "$A"
assert_not_status "500" "findings page=-5 no 500"

# ========================= CROSS-TENANT IDOR ==============================
section "IDOR — cross-tenant isolation (tenant B cannot touch A's data)"
sleep 25   # space the second tenant's registration under the 3/min auth limit
UB=$(e2e_new_user "b"); TOKB=$(echo "$UB" | cut -f1); JARB=$(echo "$UB" | cut -f3)
if [ -n "$TOKB" ] && [ "$TOKB" != "null" ]; then
    print_test "ASSET-IDOR-1 B reads A's asset"; raw_request GET "/api/v1/assets/$ASSET_A" "$TOKB" "$JARB"
    assert_status "404" "B cannot read A's asset (404)"
    print_test "FIND-IDOR-1 B reads A's finding"; raw_request GET "/api/v1/findings/$FIND_A" "$TOKB" "$JARB"
    assert_status "404" "B cannot read A's finding (404)"
    print_test "FIND-IDOR-2 B patches A's finding"; raw_request PATCH "/api/v1/findings/$FIND_A/status" "$TOKB" "$JARB" "{\"status\":\"confirmed\"}"
    assert_status "403|404" "B cannot patch A's finding"
    rm -f "$JARB"
else
    print_skip "IDOR (could not bootstrap tenant B — likely auth rate limit)"
fi

e2e_finish
