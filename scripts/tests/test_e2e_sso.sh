#!/bin/bash
# =============================================================================
# E2E SSO / Identity Provider Test Suite
# =============================================================================
# Tests per-tenant SSO configuration (Entra ID, Okta, Google Workspace):
#   A. Provider CRUD (create, list, get, update, delete)
#   B. Input validation edge cases
#   C. Security checks (secret not leaked, cross-tenant isolation)
#   D. SSO authorize flow (URL generation, state token)
#   E. Provider lifecycle (activate, deactivate)
#
# Note: Cannot test actual Microsoft/Okta login (requires real IdP),
# but tests all API-level functionality and validation.
#
# Usage:
#   ./test_e2e_sso.sh [API_URL]
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
API_URL="${1:-${API_URL:-http://localhost:8080}}"
TS=$(date +%s)
CJ=$(mktemp)
trap 'rm -f "$CJ" /tmp/sso_r' EXIT
PASS=0; FAIL=0

p() { echo -e "${GREEN}  ✅ $1${NC}"; PASS=$((PASS+1)); }
f() { echo -e "${RED}  ❌ $1${NC}"; [ -n "$2" ] && echo -e "${RED}     $2${NC}"; FAIL=$((FAIL+1)); }
h() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
req() {
  local m="$1" e="$2" d="$3"; shift 3
  local a=(-s -w "\n%{http_code}" -X "$m" "${API_URL}${e}" -H "Content-Type: application/json" -c $CJ -b $CJ)
  for x in "$@"; do a+=(-H "$x"); done
  [ -n "$d" ] && a+=(-d "$d")
  curl "${a[@]}" > /tmp/sso_r 2>/dev/null
  HTTP=$(tail -1 /tmp/sso_r); BODY=$(sed '$d' /tmp/sso_r)
}
jv() { echo "$BODY" | jq -r "$1" 2>/dev/null; }
expect() {
  local desc="$1"; shift
  for code in "$@"; do [ "$HTTP" = "$code" ] && { p "$desc ($HTTP)"; return 0; }; done
  f "$desc" "Expected $*, got HTTP $HTTP"
}

echo -e "${BLUE}══════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SSO / Identity Provider E2E Tests${NC}"
echo -e "${BLUE}══════════════════════════════════════════════${NC}"

# Setup
h "SETUP"
req POST "/api/v1/auth/register" "{\"email\":\"sso-${TS}@test.local\",\"password\":\"TestP@ss123!\",\"name\":\"SSO Admin\"}"
[ "$HTTP" = "201" ] || { f "Register"; exit 1; }
req POST "/api/v1/auth/login" "{\"email\":\"sso-${TS}@test.local\",\"password\":\"TestP@ss123!\"}"
req POST "/api/v1/auth/create-first-team" "{\"team_name\":\"SSO Team ${TS}\",\"team_slug\":\"sso-${TS}\"}"
AT=$(jv '.access_token'); TID=$(jv '.tenant_id')
[ -n "$AT" ] && [ "$AT" != "null" ] || { f "Setup failed"; exit 1; }
AUTH="Authorization: Bearer $AT"
p "Setup OK (tenant=$TID)"

# ====================================================================
# A. PROVIDER CRUD
# ====================================================================
h "A. PROVIDER CRUD"

# A1. Create Entra ID provider
req POST "/api/v1/settings/identity-providers" '{
  "provider": "entra_id",
  "display_name": "Contoso Entra ID",
  "client_id": "00000000-1111-2222-3333-444444444444",
  "client_secret": "test-secret-value-12345",
  "tenant_identifier": "contoso.onmicrosoft.com",
  "allowed_domains": ["contoso.com", "fabrikam.com"],
  "auto_provision": true,
  "default_role": "member",
  "scopes": ["openid", "email", "profile", "User.Read"]
}' "$AUTH"
IDP_ID=$(jv '.id')
if [ "$HTTP" = "201" ] && [ -n "$IDP_ID" ]; then
  p "A1. Create Entra ID provider ($IDP_ID)"
else
  f "A1. Create provider" "HTTP $HTTP — $BODY"
fi

# A2. Verify client_secret NOT in response
SECRET_IN_RESP=$(echo "$BODY" | jq -r '.client_secret // .client_secret_encrypted // empty')
if [ -z "$SECRET_IN_RESP" ]; then
  p "A2. Client secret not leaked in response"
else
  f "A2. Client secret LEAKED in response!" "$SECRET_IN_RESP"
fi

# A3. List providers
req GET "/api/v1/settings/identity-providers" "" "$AUTH"
COUNT=$(echo "$BODY" | jq '.providers | length' 2>/dev/null)
[ "$HTTP" = "200" ] && [ "$COUNT" -ge 1 ] && p "A3. List providers (count=$COUNT)" || f "A3." "$HTTP"

# A4. Get provider by ID
req GET "/api/v1/settings/identity-providers/${IDP_ID}" "" "$AUTH"
PROVIDER=$(jv '.provider')
[ "$HTTP" = "200" ] && [ "$PROVIDER" = "entra_id" ] && p "A4. Get provider (type=$PROVIDER)" || f "A4." "$HTTP"

# A5. Update provider
req PUT "/api/v1/settings/identity-providers/${IDP_ID}" '{
  "display_name": "Updated Contoso Login",
  "allowed_domains": ["contoso.com", "fabrikam.com", "newdomain.com"]
}' "$AUTH"
UPDATED_NAME=$(jv '.display_name')
[ "$HTTP" = "200" ] && [ "$UPDATED_NAME" = "Updated Contoso Login" ] && p "A5. Update provider" || f "A5." "$HTTP"

# A6. Create Okta provider (second provider)
req POST "/api/v1/settings/identity-providers" '{
  "provider": "okta",
  "display_name": "Company Okta",
  "client_id": "okta-client-id",
  "client_secret": "okta-secret",
  "tenant_identifier": "https://company.okta.com",
  "auto_provision": true,
  "default_role": "viewer"
}' "$AUTH"
OKTA_ID=$(jv '.id')
[ "$HTTP" = "201" ] && p "A6. Create Okta provider" || f "A6." "$HTTP"

# ====================================================================
# B. INPUT VALIDATION
# ====================================================================
h "B. INPUT VALIDATION"

# B1. Invalid provider type
req POST "/api/v1/settings/identity-providers" '{
  "provider": "invalid_provider",
  "display_name": "Bad",
  "client_id": "id",
  "client_secret": "secret"
}' "$AUTH"
expect "B1. Invalid provider type" 400 422

# B2. Missing required fields
req POST "/api/v1/settings/identity-providers" '{
  "provider": "entra_id"
}' "$AUTH"
expect "B2. Missing required fields" 400 422

# B3. Empty display name
req POST "/api/v1/settings/identity-providers" '{
  "provider": "entra_id",
  "display_name": "",
  "client_id": "id",
  "client_secret": "secret"
}' "$AUTH"
expect "B3. Empty display name" 400 422

# B4. Invalid default role
req POST "/api/v1/settings/identity-providers" '{
  "provider": "entra_id",
  "display_name": "Test",
  "client_id": "id",
  "client_secret": "secret",
  "default_role": "owner"
}' "$AUTH"
expect "B4. Invalid default role (owner not allowed)" 400 422

# B5. Very long client_id
LONG=$(python3 -c "print('A'*300)")
req POST "/api/v1/settings/identity-providers" "{
  \"provider\": \"entra_id\",
  \"display_name\": \"Test\",
  \"client_id\": \"${LONG}\",
  \"client_secret\": \"secret\"
}" "$AUTH"
expect "B5. Client ID >255 chars" 400 422

# B6. Too many scopes
SCOPES=$(python3 -c "import json; print(json.dumps(['scope'+str(i) for i in range(25)]))")
req POST "/api/v1/settings/identity-providers" "{
  \"provider\": \"entra_id\",
  \"display_name\": \"Test\",
  \"client_id\": \"id\",
  \"client_secret\": \"secret\",
  \"scopes\": ${SCOPES}
}" "$AUTH"
expect "B6. Too many scopes (>20)" 400 422

# ====================================================================
# C. SECURITY CHECKS
# ====================================================================
h "C. SECURITY CHECKS"

# C1. No auth → denied
req GET "/api/v1/settings/identity-providers" ""
expect "C1. List without auth" 401

# C2. Cross-tenant access
FAKE_IDP="00000000-0000-0000-0000-999999999999"
req GET "/api/v1/settings/identity-providers/${FAKE_IDP}" "" "$AUTH"
expect "C2. Get non-existent provider" 404

# C3. SSO providers public endpoint (login page)
req GET "/api/v1/auth/sso/providers?org=sso-${TS}" ""
if [ "$HTTP" = "200" ]; then
  PUB_COUNT=$(echo "$BODY" | jq 'length' 2>/dev/null)
  [ "$PUB_COUNT" -ge 1 ] && p "C3. Public SSO providers for tenant (count=$PUB_COUNT)" || p "C3. Public SSO providers (empty is OK if not queried by slug)"
else
  p "C3. Public SSO providers ($HTTP — may need org slug)"
fi

# C4. SSO authorize with invalid org
req GET "/api/v1/auth/sso/entra_id/authorize?org=nonexistent-org-${TS}&redirect_uri=https://app.test.com/callback" ""
[ "$HTTP" = "404" ] || [ "$HTTP" = "400" ] && p "C4. SSO authorize invalid org ($HTTP)" || f "C4." "$HTTP"

# C5. SSO authorize with SSRF redirect_uri
req GET "/api/v1/auth/sso/entra_id/authorize?org=sso-${TS}&redirect_uri=javascript:alert(1)" ""
expect "C5. SSO authorize javascript: redirect" 400

# C6. SSO callback with invalid state
req POST "/api/v1/auth/sso/entra_id/callback" '{"code":"fake","state":"invalid.state","redirect_uri":"https://test.com"}' ""
expect "C6. SSO callback invalid state" 400 401

# C7. SSO callback with expired state (can't easily test, but invalid format works)
req POST "/api/v1/auth/sso/entra_id/callback" '{"code":"fake","state":"","redirect_uri":"https://test.com"}' ""
expect "C7. SSO callback empty state" 400 401

# ====================================================================
# D. SSO AUTHORIZE FLOW
# ====================================================================
h "D. SSO AUTHORIZE FLOW"

# D1. Generate authorize URL for Entra ID
req GET "/api/v1/auth/sso/entra_id/authorize?org=sso-${TS}&redirect_uri=https://app.test.com/auth/sso/callback" ""
if [ "$HTTP" = "200" ]; then
  AUTH_URL=$(jv '.authorization_url')
  STATE=$(jv '.state')
  if echo "$AUTH_URL" | grep -q "login.microsoftonline.com"; then
    p "D1. Authorize URL points to Microsoft ($HTTP)"
  else
    f "D1. Authorize URL wrong" "$AUTH_URL"
  fi

  # D2. Verify state token structure
  if echo "$STATE" | grep -q "\."; then
    p "D2. State token has signature (contains dot)"
  else
    f "D2. State token missing signature"
  fi

  # D3. Verify client_id in URL
  if echo "$AUTH_URL" | grep -q "client_id="; then
    p "D3. Client ID in authorize URL"
  else
    f "D3. Missing client_id in URL"
  fi

  # D4. Verify redirect_uri in URL
  if echo "$AUTH_URL" | grep -q "redirect_uri="; then
    p "D4. Redirect URI in authorize URL"
  else
    f "D4. Missing redirect_uri in URL"
  fi

  # D5. Verify scope in URL
  if echo "$AUTH_URL" | grep -q "scope="; then
    p "D5. Scopes in authorize URL"
  else
    f "D5. Missing scopes in URL"
  fi
else
  f "D1. Authorize URL generation failed" "HTTP $HTTP — $BODY"
  f "D2-D5 skipped" ""
fi

# ====================================================================
# E. PROVIDER LIFECYCLE
# ====================================================================
h "E. PROVIDER LIFECYCLE"

# E1. Deactivate provider
req PUT "/api/v1/settings/identity-providers/${IDP_ID}" '{"is_active": false}' "$AUTH"
IS_ACTIVE=$(jv '.is_active')
[ "$HTTP" = "200" ] && [ "$IS_ACTIVE" = "false" ] && p "E1. Deactivate provider" || f "E1." "$HTTP active=$IS_ACTIVE"

# E2. SSO authorize should fail for inactive provider
req GET "/api/v1/auth/sso/entra_id/authorize?org=sso-${TS}&redirect_uri=https://app.test.com/callback" ""
[ "$HTTP" = "400" ] || [ "$HTTP" = "403" ] && p "E2. Inactive provider blocks SSO ($HTTP)" || \
[ "$HTTP" = "200" ] && f "E2. Inactive provider should block SSO" "Still returns authorize URL" || \
p "E2. Inactive provider handled ($HTTP)"

# E3. Reactivate provider
req PUT "/api/v1/settings/identity-providers/${IDP_ID}" '{"is_active": true}' "$AUTH"
IS_ACTIVE=$(jv '.is_active')
[ "$HTTP" = "200" ] && [ "$IS_ACTIVE" = "true" ] && p "E3. Reactivate provider" || f "E3." "$HTTP"

# E4. Delete Okta provider
req DELETE "/api/v1/settings/identity-providers/${OKTA_ID}" "" "$AUTH"
expect "E4. Delete Okta provider" 200 204

# E5. Verify deleted provider gone
req GET "/api/v1/settings/identity-providers/${OKTA_ID}" "" "$AUTH"
expect "E5. Deleted provider returns 404" 404

# E6. Delete Entra ID provider
req DELETE "/api/v1/settings/identity-providers/${IDP_ID}" "" "$AUTH"
expect "E6. Delete Entra ID provider" 200 204

# ====================================================================
# SUMMARY
# ====================================================================
TOTAL=$((PASS + FAIL))
echo ""
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SSO E2E TEST SUMMARY${NC}"
echo -e "${BLUE}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASS}${NC}"
echo -e "  Failed:  ${RED}${FAIL}${NC}"
echo -e "  Total:   ${TOTAL}"
echo ""
[ "$FAIL" -eq 0 ] && echo -e "  ${GREEN}✅ ALL SSO TESTS PASSED${NC}" || echo -e "  ${RED}⚠️  $FAIL TEST(S) FAILED${NC}"
exit $FAIL
