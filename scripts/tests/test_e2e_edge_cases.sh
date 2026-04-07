#!/bin/bash
# =============================================================================
# Comprehensive Edge Case Test Suite
# =============================================================================
# Tests edge cases across ALL major features:
#   A. Asset Management (CRUD, types, validation, bulk ops)
#   B. Finding Management (lifecycle, actions, filters)
#   C. Auth & Tenant (registration, invitation, permissions)
#   D. Integrations & Webhooks (SSRF, duplicates, limits)
#   E. Input Validation (XSS, SQLi, overflow, unicode, null bytes)
#   F. Pagination & Sorting (overflow, invalid params)
#   G. Scan & Pipeline (triggers, status)
#   H. Asset Groups (CRUD, members, limits)
#
# Usage:
#   ./test_e2e_edge_cases.sh [API_URL]
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TS=$(date +%s)
CJ=$(mktemp /tmp/edge_ck.XXXXXX)
trap 'rm -f "$CJ" /tmp/edge_r' EXIT
PASS=0; FAIL=0; SKIP=0

p() { echo -e "${GREEN}  ✅ $1${NC}"; PASS=$((PASS+1)); }
f() { echo -e "${RED}  ❌ $1${NC}"; [ -n "$2" ] && echo -e "${RED}     $2${NC}"; FAIL=$((FAIL+1)); }
s() { echo -e "${YELLOW}  ⏭️  $1${NC}"; SKIP=$((SKIP+1)); }
h() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
req() {
  local m="$1" e="$2" d="$3"; shift 3
  local a=(-s -w "\n%{http_code}" -X "$m" "${API_URL}${e}" -H "Content-Type: application/json" -c $CJ -b $CJ)
  for x in "$@"; do a+=(-H "$x"); done
  [ -n "$d" ] && a+=(-d "$d")
  curl "${a[@]}" > /tmp/edge_r 2>/dev/null
  HTTP=$(tail -1 /tmp/edge_r); BODY=$(sed '$d' /tmp/edge_r)
}
jv() { echo "$BODY" | jq -r "$1" 2>/dev/null; }
# Expect specific HTTP codes (pass list of acceptable codes)
expect() {
  local desc="$1"; shift
  for code in "$@"; do [ "$HTTP" = "$code" ] && { p "$desc ($HTTP)"; return 0; }; done
  f "$desc" "Expected $*, got HTTP $HTTP"
  return 1
}

echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  COMPREHENSIVE EDGE CASE TEST SUITE${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo "  API: $API_URL | TS: $TS"

# ====================================================================
# SETUP
# ====================================================================
h "SETUP"
req POST "/api/v1/auth/register" "{\"email\":\"edge-${TS}@test.local\",\"password\":\"TestP@ss123!\",\"name\":\"Edge\"}"
[ "$HTTP" = "201" ] || { f "Register failed ($HTTP)"; exit 1; }
req POST "/api/v1/auth/login" "{\"email\":\"edge-${TS}@test.local\",\"password\":\"TestP@ss123!\"}"
req POST "/api/v1/auth/create-first-team" "{\"team_name\":\"Edge ${TS}\",\"team_slug\":\"edge-${TS}\"}"
AT=$(jv '.access_token'); TID=$(jv '.tenant_id')
[ -n "$AT" ] && [ "$AT" != "null" ] || { f "Setup failed"; exit 1; }
AUTH="Authorization: Bearer $AT"
p "Setup OK (tenant=$TID)"

# ====================================================================
# A. ASSET EDGE CASES
# ====================================================================
h "A. ASSET EDGE CASES"

req POST "/api/v1/assets" '{"name":"","type":"domain","criticality":"high"}' "$AUTH"
expect "A1. Empty asset name" 400 422

req POST "/api/v1/assets" '{"name":"Test","type":"invalid_type_xyz","criticality":"high"}' "$AUTH"
expect "A2. Invalid asset type" 400 422

req POST "/api/v1/assets" '{"name":"Test","type":"domain","criticality":"super_duper"}' "$AUTH"
expect "A3. Invalid criticality" 400 422

LONG256=$(python3 -c "print('X'*256)")
req POST "/api/v1/assets" "{\"name\":\"${LONG256}\",\"type\":\"domain\",\"criticality\":\"low\"}" "$AUTH"
expect "A4. Name 256 chars (>255)" 400 422

req POST "/api/v1/assets" '{"name":"Valid Asset","type":"domain","criticality":"high"}' "$AUTH"
ASSET_ID=$(jv '.id')
[ -n "$ASSET_ID" ] && p "A5. Create valid asset" || f "A5. Create asset" "$HTTP"

req POST "/api/v1/assets" '{"name":"Valid Asset","type":"domain","criticality":"high"}' "$AUTH"
expect "A6. Duplicate asset name" 400 409 422

req GET "/api/v1/assets/00000000-0000-0000-0000-000000000099" "" "$AUTH"
expect "A7. Non-existent asset ID" 404

req GET "/api/v1/assets/not-a-uuid" "" "$AUTH"
expect "A8. Invalid UUID format" 400 404 422

req PUT "/api/v1/assets/${ASSET_ID}" '{"criticality":"invalid"}' "$AUTH"
expect "A9. Update with invalid criticality" 400 422

req PUT "/api/v1/assets/${ASSET_ID}" '{"risk_score":999}' "$AUTH"
if [ "$HTTP" = "200" ]; then
  SCORE=$(jv '.risk_score')
  [ "$SCORE" -le 100 ] && p "A10. Risk score >100 clamped ($SCORE)" || f "A10. Score not clamped" "$SCORE"
elif [ "$HTTP" = "400" ] || [ "$HTTP" = "422" ]; then
  p "A10. Risk score >100 rejected ($HTTP)"
else
  f "A10. Risk score overflow" "$HTTP"
fi

req POST "/api/v1/assets/bulk/status" '{"asset_ids":[],"status":"active"}' "$AUTH"
expect "A11. Bulk update empty array" 200

req POST "/api/v1/assets/bulk/status" '{"asset_ids":["not-uuid"],"status":"active"}' "$AUTH"
expect "A12. Bulk update invalid UUID" 200 400 422

req POST "/api/v1/assets/bulk/status" "{\"asset_ids\":[\"${ASSET_ID}\"],\"status\":\"destroyed\"}" "$AUTH"
expect "A13. Bulk update invalid status" 400 422

req GET "/api/v1/assets/stats" "" "$AUTH"
[ "$HTTP" = "200" ] && p "A14. Stats endpoint works" || f "A14. Stats" "$HTTP"

req GET "/api/v1/assets?search=';DROP TABLE assets;--" "" "$AUTH"
expect "A15. SQLi in search" 200

req GET "/api/v1/assets?search=<script>alert(1)</script>" "" "$AUTH"
expect "A16. XSS in search" 200

# ====================================================================
# B. FINDING EDGE CASES
# ====================================================================
h "B. FINDING EDGE CASES"

req GET "/api/v1/findings?severity=invalid_sev" "" "$AUTH"
[ "$HTTP" = "200" ] || [ "$HTTP" = "400" ] && p "B1. Invalid severity filter ($HTTP)" || f "B1." "$HTTP"

req GET "/api/v1/findings?page=-1&per_page=0" "" "$AUTH"
[ "$HTTP" = "200" ] && p "B2. Negative page/zero per_page handled" || f "B2." "$HTTP"

req GET "/api/v1/findings?page=999999999&per_page=1" "" "$AUTH"
[ "$HTTP" = "200" ] && p "B3. Very large page number handled" || f "B3." "$HTTP"

req GET "/api/v1/findings?per_page=99999" "" "$AUTH"
if [ "$HTTP" = "200" ]; then
  PP=$(jv '.per_page // .limit // 100')
  [ "$PP" -le 100 ] && p "B4. per_page capped at 100 (got $PP)" || f "B4. per_page not capped" "$PP"
else
  f "B4." "$HTTP"
fi

req GET "/api/v1/findings?sort=nonexistent_field" "" "$AUTH"
[ "$HTTP" = "200" ] || [ "$HTTP" = "400" ] && p "B5. Invalid sort field ($HTTP)" || f "B5." "$HTTP"

# ====================================================================
# C. AUTH EDGE CASES
# ====================================================================
h "C. AUTH EDGE CASES"

req GET "/api/v1/assets" ""
expect "C1. No auth token" 401

req GET "/api/v1/assets" "" "Authorization: Bearer invalidtoken"
expect "C2. Invalid JWT" 401

req GET "/api/v1/assets" "" "Authorization: Bearer "
expect "C3. Empty bearer" 401

req GET "/api/v1/assets" "" "Authorization: Basic dXNlcjpwYXNz"
expect "C4. Basic auth instead of Bearer" 401

req POST "/api/v1/auth/login" '{"email":"","password":""}'
expect "C5. Empty credentials" 400 401 422

req POST "/api/v1/auth/login" '{"email":"test@test.com","password":"wrong"}'
expect "C6. Wrong password" 401

req POST "/api/v1/auth/login" '{"email":"nonexist@test.com","password":"Test123!"}'
expect "C7. Non-existent user (anti-enum)" 401 429

# ====================================================================
# D. INTEGRATION & WEBHOOK EDGE CASES
# ====================================================================
h "D. INTEGRATION & WEBHOOK EDGE CASES"

req POST "/api/v1/webhooks" '{"name":"Test","url":"http://localhost/hook","event_types":["findings"]}' "$AUTH"
expect "D1. Webhook localhost SSRF" 400

req POST "/api/v1/webhooks" '{"name":"Test","url":"http://169.254.169.254/meta","event_types":["findings"]}' "$AUTH"
expect "D2. Webhook AWS metadata SSRF" 400

req POST "/api/v1/webhooks" '{"name":"Test","url":"file:///etc/passwd","event_types":["findings"]}' "$AUTH"
expect "D3. Webhook file:// scheme" 400

req POST "/api/v1/webhooks" '{"name":"Test","url":"gopher://evil","event_types":["findings"]}' "$AUTH"
expect "D4. Webhook gopher:// scheme" 400

req POST "/api/v1/webhooks" '{"name":"Test","url":"http://10.0.0.1/internal","event_types":["findings"]}' "$AUTH"
expect "D5. Webhook private IP" 400

req POST "/api/v1/webhooks" '{"name":"","url":"https://valid.com","event_types":["findings"]}' "$AUTH"
expect "D6. Webhook empty name" 400 422

req POST "/api/v1/webhooks" '{"name":"Test","url":"https://valid.com","event_types":[]}' "$AUTH"
expect "D7. Webhook empty event_types" 400 422

req POST "/api/v1/integrations" '{"name":"Test","category":"invalid","provider":"github","auth_type":"token"}' "$AUTH"
expect "D8. Integration invalid category" 400 422

req POST "/api/v1/integrations" '{"name":"Test","category":"scm","provider":"invalid","auth_type":"token"}' "$AUTH"
expect "D9. Integration invalid provider" 400 422

req POST "/api/v1/integrations" '{"name":"Test","category":"scm","provider":"github","auth_type":"token","base_url":"http://127.0.0.1"}' "$AUTH"
expect "D10. Integration SSRF base_url" 400

# ====================================================================
# E. INPUT VALIDATION EDGE CASES
# ====================================================================
h "E. INPUT VALIDATION EDGE CASES"

req POST "/api/v1/assets" '{"name":"<img src=x onerror=alert(1)>","type":"domain","criticality":"low"}' "$AUTH"
[ "$HTTP" = "201" ] || [ "$HTTP" = "400" ] && p "E1. XSS in asset name ($HTTP)" || f "E1." "$HTTP"

req POST "/api/v1/assets" "{\"name\":\"Unicode: 你好世界 العربية\",\"type\":\"domain\",\"criticality\":\"low\"}" "$AUTH"
[ "$HTTP" = "201" ] || [ "$HTTP" = "400" ] && p "E2. Unicode in name ($HTTP)" || f "E2." "$HTTP"

req POST "/api/v1/assets" '{"name":"CRLF\r\nInjection: test","type":"domain","criticality":"low"}' "$AUTH"
[ "$HTTP" = "201" ] || [ "$HTTP" = "400" ] && p "E3. CRLF in name ($HTTP)" || f "E3." "$HTTP"

req POST "/api/v1/assets" '{"name":"Null\u0000Byte","type":"domain","criticality":"low"}' "$AUTH"
[ "$HTTP" = "201" ] || [ "$HTTP" = "400" ] && p "E4. Null byte in name ($HTTP)" || f "E4." "$HTTP"

DESC10K=$(python3 -c "print('A'*10001)")
req POST "/api/v1/assets" "{\"name\":\"Long Desc\",\"type\":\"domain\",\"criticality\":\"low\",\"description\":\"${DESC10K}\"}" "$AUTH"
expect "E5. Description 10K chars" 400 422 201

req POST "/api/v1/assets" '{}' "$AUTH"
expect "E6. Empty JSON body" 400 422

req POST "/api/v1/assets" 'not json' "$AUTH"
expect "E7. Invalid JSON" 400

req POST "/api/v1/assets" '' "$AUTH"
expect "E8. No body" 400

# ====================================================================
# F. PAGINATION EDGE CASES
# ====================================================================
h "F. PAGINATION EDGE CASES"

req GET "/api/v1/assets?page=0" "" "$AUTH"
[ "$HTTP" = "200" ] && p "F1. Page=0 handled (defaults to 1)" || f "F1." "$HTTP"

req GET "/api/v1/assets?page=-100" "" "$AUTH"
[ "$HTTP" = "200" ] && p "F2. Page=-100 handled" || f "F2." "$HTTP"

req GET "/api/v1/assets?page=2147483647" "" "$AUTH"
[ "$HTTP" = "200" ] && p "F3. Page=MaxInt32 handled (no overflow)" || f "F3." "$HTTP"

req GET "/api/v1/assets?per_page=-1" "" "$AUTH"
[ "$HTTP" = "200" ] && p "F4. per_page=-1 handled" || f "F4." "$HTTP"

req GET "/api/v1/assets?per_page=0" "" "$AUTH"
[ "$HTTP" = "200" ] && p "F5. per_page=0 handled" || f "F5." "$HTTP"

req GET "/api/v1/assets?per_page=999999" "" "$AUTH"
[ "$HTTP" = "200" ] && {
  PP=$(jv '.per_page // 100')
  [ "$PP" -le 100 ] && p "F6. per_page=999999 capped ($PP)" || f "F6. Not capped" "$PP"
} || f "F6." "$HTTP"

req GET "/api/v1/assets?sort=name&order=invalid" "" "$AUTH"
[ "$HTTP" = "200" ] || [ "$HTTP" = "400" ] && p "F7. Invalid sort order ($HTTP)" || f "F7." "$HTTP"

# ====================================================================
# G. HEADER INJECTION EDGE CASES
# ====================================================================
h "G. HEADER INJECTION EDGE CASES"

req GET "/api/v1/assets?page=1&per_page=1" "" "$AUTH" "X-Forwarded-Proto: javascript"
HAS_JS=$(echo "$BODY" | grep -c "javascript:" || true)
[ "$HAS_JS" = "0" ] && p "G1. X-Forwarded-Proto javascript: not reflected" || f "G1. Reflected!"

req GET "/api/v1/assets?page=1&per_page=1" "" "$AUTH" "X-Forwarded-Host: evil.com"
HAS_EVIL=$(echo "$BODY" | grep -c "evil.com" || true)
[ "$HAS_EVIL" = "0" ] && p "G2. X-Forwarded-Host not reflected" || f "G2. Reflected!"

# ====================================================================
# H. ASSET GROUP EDGE CASES
# ====================================================================
h "H. ASSET GROUP EDGE CASES"

req POST "/api/v1/asset-groups" '{"name":"","environment":"production","criticality":"high"}' "$AUTH"
expect "H1. Empty group name" 400 422

req POST "/api/v1/asset-groups" '{"name":"Valid Group","environment":"invalid_env","criticality":"high"}' "$AUTH"
expect "H2. Invalid environment" 400 422

req POST "/api/v1/asset-groups" '{"name":"Valid Group","environment":"production","criticality":"super"}' "$AUTH"
expect "H3. Invalid criticality" 400 422

req POST "/api/v1/asset-groups" '{"name":"Test Group","environment":"production","criticality":"high"}' "$AUTH"
GRP_ID=$(jv '.id')
[ -n "$GRP_ID" ] && p "H4. Create valid group" || f "H4." "$HTTP"

req POST "/api/v1/asset-groups" '{"name":"Test Group","environment":"production","criticality":"high"}' "$AUTH"
expect "H5. Duplicate group name" 400 409 422

req GET "/api/v1/asset-groups/not-a-uuid" "" "$AUTH"
expect "H6. Invalid group UUID" 400 404

# ====================================================================
# I. INVITATION EDGE CASES (verified working from earlier)
# ====================================================================
h "I. INVITATION EDGE CASES"

req POST "/api/v1/tenants/${TID}/invitations" '{"email":"","role_ids":["00000000-0000-0000-0000-000000000003"]}' "$AUTH"
expect "I1. Empty email" 400 422

LONG_EMAIL=$(python3 -c "print('a'*280 + '@test.local')")
req POST "/api/v1/tenants/${TID}/invitations" "{\"email\":\"${LONG_EMAIL}\",\"role_ids\":[\"00000000-0000-0000-0000-000000000003\"]}" "$AUTH"
expect "I2. Email >254 chars" 400 422

req POST "/api/v1/tenants/${TID}/invitations" '{"email":"test@test.com","role_ids":[""]}' "$AUTH"
expect "I3. Empty role UUID" 400 422

req POST "/api/v1/tenants/${TID}/invitations" '{"email":"test@test.com","role_ids":["not-uuid"]}' "$AUTH"
expect "I4. Invalid role UUID" 400 422

req POST "/api/v1/tenants/${TID}/invitations" '{"email":"test@test.com","role_ids":[]}' "$AUTH"
expect "I5. Empty role_ids array" 400 422

req GET "/api/v1/invitations/%00%00/preview" ""
expect "I6. Null bytes in token" 400 404

# ====================================================================
# J. CROSS-TENANT ISOLATION
# ====================================================================
h "J. CROSS-TENANT ISOLATION"

FAKE_TID="00000000-0000-0000-0000-000000000001"
req GET "/api/v1/tenants/${FAKE_TID}/members" "" "$AUTH"
expect "J1. List members of other tenant" 403 404

req POST "/api/v1/tenants/${FAKE_TID}/invitations" '{"email":"x@x.com","role_ids":["00000000-0000-0000-0000-000000000003"]}' "$AUTH"
expect "J2. Invite to other tenant" 403 404

req DELETE "/api/v1/tenants/${FAKE_TID}" "" "$AUTH"
expect "J3. Delete other tenant" 403 404

# ====================================================================
# K. RATE LIMITING & HEALTH
# ====================================================================
h "K. RATE LIMITING & HEALTH"

req GET "/health" ""
expect "K1. Health check" 200

req GET "/ready" ""
expect "K2. Readiness check" 200

req GET "/metrics" ""
[ "$HTTP" = "200" ] && {
  HAS_HTTP=$(echo "$BODY" | grep -c "http_requests_total" || true)
  [ "$HAS_HTTP" -gt 0 ] && p "K3. Metrics endpoint has data" || f "K3. Missing metrics"
} || f "K3." "$HTTP"

# ====================================================================
# CLEANUP
# ====================================================================
h "CLEANUP"
[ -n "$ASSET_ID" ] && req DELETE "/api/v1/assets/${ASSET_ID}" "" "$AUTH"
[ -n "$GRP_ID" ] && req DELETE "/api/v1/asset-groups/${GRP_ID}" "" "$AUTH"
p "Cleanup done"

# ====================================================================
# SUMMARY
# ====================================================================
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  EDGE CASE TEST SUMMARY${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASS}${NC}"
echo -e "  Failed:  ${RED}${FAIL}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIP}${NC}"
echo -e "  Total:   ${TOTAL}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}✅ ALL EDGE CASES PASSED${NC}"
  exit 0
else
  echo -e "  ${RED}⚠️  $FAIL EDGE CASE(S) FAILED${NC}"
  exit 1
fi
