#!/bin/bash
# =============================================================================
# E2E CTEM Full-Lifecycle Flow — one realistic journey across EVERY feature area
# =============================================================================
# Registers ONCE (avoids the auth 3/min rate limit that breaks bulk per-script
# runs) then walks the whole product surface with an assertion at every step, so
# a bug in ANY step of ANY feature fails loudly.
#
#   ./test_e2e_ctem_lifecycle.sh [API_URL]
# =============================================================================
source "$(cd "$(dirname "$0")" && pwd)/_e2e_common.sh"
e2e_init "ctem-lifecycle"
e2e_bootstrap_auth
A="$(auth_hdr)"

section() { echo -e "\n${BLUE}──── $1 ────${NC}"; }

# ============================ IDENTITY / TENANT ==============================
section "Identity & tenant"
print_test "GET /users/me"; do_request GET /api/v1/users/me "" "$A"
assert_status 200 "me"; assert_json '.email' "me has email"
print_test "GET tenant members"; do_request GET "/api/v1/tenants/${TENANT_ID}/members" "" "$A"
assert_not_status 500 "list members no 500"

# ================================ ASSETS ====================================
section "Assets"
print_test "create asset"; do_request POST /api/v1/assets \
    "{\"name\":\"lc-${TIMESTAMP}.example.com\",\"type\":\"domain\",\"criticality\":\"high\"}" "$A"
assert_status "200|201" "create asset"; ASSET_ID=$(extract_json "$BODY" '.id')
print_test "get asset"; do_request GET "/api/v1/assets/${ASSET_ID}" "" "$A"
assert_status 200 "get asset"; assert_json '.id=="'"$ASSET_ID"'"' "asset id matches"
print_test "list assets"; do_request GET "/api/v1/assets?page=1&per_page=20" "" "$A"
assert_status 200 "list assets"; assert_json '(.data // .items | length) >= 1' "asset in list"
print_test "get missing asset -> 404"; do_request GET /api/v1/assets/00000000-0000-0000-0000-000000000000 "" "$A"
assert_status "404" "missing asset 404"

# =============================== FINDINGS ===================================
section "Findings lifecycle"
print_test "create finding"; do_request POST /api/v1/findings "{
    \"asset_id\":\"$ASSET_ID\",\"source\":\"sast\",\"tool_name\":\"semgrep\",
    \"rule_id\":\"lc-${TIMESTAMP}\",\"message\":\"lifecycle finding\",\"severity\":\"high\",
    \"file_path\":\"a.go\",\"start_line\":1,\"end_line\":1}" "$A"
assert_status "200|201" "create finding"; FINDING_ID=$(extract_json "$BODY" '.id')
print_test "get finding"; do_request GET "/api/v1/findings/${FINDING_ID}" "" "$A"
assert_status 200 "get finding"
print_test "finding stats"; do_request GET /api/v1/findings/stats "" "$A"
assert_status 200 "finding stats"
print_test "findings/groups page 1 (regression #234)"; do_request GET "/api/v1/findings/groups?group_by=severity&page=1&per_page=20" "" "$A"
assert_status 200 "findings groups"; assert_json '(.data|length) >= 1' "groups page1 not empty"
print_test "status: confirm finding"; do_request PATCH "/api/v1/findings/${FINDING_ID}/status" \
    "{\"status\":\"confirmed\"}" "$A"
assert_status "200|204" "confirm finding"
print_test "add comment"; do_request POST "/api/v1/findings/${FINDING_ID}/comments" \
    "{\"content\":\"triaging via e2e\"}" "$A"
assert_status "200|201" "add comment"
print_test "finding activities"; do_request GET "/api/v1/findings/${FINDING_ID}/activities" "" "$A"
assert_not_status 500 "activities no 500"
print_test "bulk fix-applied exposes 'failed' (regression #241)"; do_request POST /api/v1/findings/actions/fix-applied \
    "{\"filter\":{\"cve_ids\":[]},\"note\":\"e2e probe\"}" "$A"
assert_status "200|201" "fix-applied"; assert_json 'has("failed")' "result has failed field"

# =============================== EXPOSURES ==================================
section "Exposures"
print_test "list exposures"; do_request GET "/api/v1/exposures?page=1&per_page=20" "" "$A"
assert_status 200 "list exposures"
print_test "exposure stats"; do_request GET /api/v1/exposures/stats "" "$A"
assert_not_status 500 "exposure stats no 500"
print_test "invalid exposure filter -> 400 (regression #238)"; do_request GET "/api/v1/exposures?severity=criticl" "" "$A"
assert_status 400 "invalid filter rejected"

# ========================= REMEDIATION CAMPAIGN =============================
section "Remediation campaigns"
print_test "create campaign"; do_request POST /api/v1/remediation/campaigns \
    "{\"name\":\"lc campaign ${TIMESTAMP}\",\"priority\":\"high\",\"finding_filter\":{\"severities\":[\"high\"]}}" "$A"
if echo "$HTTP_CODE" | grep -qE '^(200|201)$'; then
    print_success "create campaign (HTTP $HTTP_CODE)"; CAMPAIGN_ID=$(extract_json "$BODY" '.id')
    print_test "campaign progress in [0,100] (regression #242)"; do_request GET "/api/v1/remediation/campaigns/${CAMPAIGN_ID}" "" "$A"
    assert_json '((.completion_percentage // .progress // 0)|tonumber) >= 0 and ((.completion_percentage // .progress // 0)|tonumber) <= 100' "campaign progress <=100"
else
    print_skip "remediation campaign create (HTTP $HTTP_CODE)"
fi

# =============================== COMPLIANCE =================================
section "Compliance"
print_test "list frameworks"; do_request GET /api/v1/compliance/frameworks "" "$A"
assert_status 200 "list frameworks"
FW_ID=$(extract_json "$BODY" '(.data // .items // [])[0].id // empty')
if [ -n "$FW_ID" ]; then
    print_test "framework score in [0,100] (regression #230)"; do_request GET "/api/v1/compliance/frameworks/${FW_ID}/stats" "" "$A"
    assert_json '(.compliance_score // .score // 0) >= 0 and (.compliance_score // .score // 0) <= 100' "score in [0,100]"
else
    print_skip "no seeded framework"
fi

# =============================== DASHBOARD ==================================
section "Dashboard"
print_test "dashboard stats"; do_request GET /api/v1/dashboard/stats "" "$A"
assert_not_status 500 "dashboard stats no 500"

# =========================== SCANS / TOOLS ==================================
section "Scans & tools"
print_test "list tools"; do_request GET /api/v1/tools "" "$A"
assert_status 200 "list tools"
print_test "list scan profiles"; do_request GET /api/v1/scan-profiles "" "$A"
assert_not_status 500 "scan profiles no 500"

# ============================ THREAT INTEL =================================
section "Threat intel"
print_test "list threat actors"; do_request GET /api/v1/threat-actors "" "$A"
assert_status 200 "list actors"
print_test "delete actor malformed id -> 400 (regression #236)"; do_request DELETE /api/v1/threat-actors/not-a-uuid "" "$A"
assert_status 400 "malformed actor id 400"

# =============================== WORKFLOWS ==================================
section "Workflows"
print_test "list workflows"; do_request GET /api/v1/workflows "" "$A"
assert_not_status 500 "workflows no 500"

# ================================= AUDIT ===================================
section "Audit"
print_test "list audit logs"; do_request GET "/api/v1/audit-logs?page=1&per_page=20" "" "$A"
assert_status 200 "list audit"
print_test "audit resource history ?per_page=0 no panic (regression #234)"; do_request GET "/api/v1/audit-logs/resource/finding/${FINDING_ID}?per_page=0" "" "$A"
assert_not_status 500 "audit per_page=0 no 500"

# ============================== COMPONENTS =================================
section "Components"
print_test "missing component -> 404 (regression #233)"; do_request GET /api/v1/components/00000000-0000-0000-0000-000000000000 "" "$A"
assert_status 404 "missing component 404"

e2e_finish
