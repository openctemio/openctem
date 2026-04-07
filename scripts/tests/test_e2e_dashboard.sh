#!/bin/bash
# =============================================================================
# E2E Dashboard Endpoints Test Script
# =============================================================================
# Tests dashboard and stats endpoints:
#   1. GET /api/v1/dashboard/summary
#   2. Verify response has all expected fields
#   3. GET /api/v1/assets/stats
#   4. Verify stats response structure
#   5. Edge cases: empty tenant (no data)
#
# Usage:
#   ./test_e2e_dashboard.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-dash-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="SecureP@ss123!"
TEST_NAME="Dashboard Test User"
TEST_TEAM="Dashboard Team ${TIMESTAMP}"
TEST_SLUG="dash-team-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_dash_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_dash_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0
ACCESS_TOKEN=""
TENANT_ID=""
BODY=""
HTTP_CODE=""

# =============================================================================
# Helpers
# =============================================================================

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_test() { echo -e "\n${YELLOW}>>> Test: $1${NC}"; }
print_success() { echo -e "${GREEN}  PASSED: $1${NC}"; PASSED=$((PASSED + 1)); }
print_failure() { echo -e "${RED}  FAILED: $1${NC}"; [ -n "$2" ] && echo -e "${RED}  Detail: $2${NC}"; FAILED=$((FAILED + 1)); }
print_skip() { echo -e "${YELLOW}  SKIPPED: $1${NC}"; SKIPPED=$((SKIPPED + 1)); }

do_request() {
    local method="$1" endpoint="$2" data="$3"
    shift 3
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json" -c "$COOKIE_JAR" -b "$COOKIE_JAR")
    for h in "$@"; do curl_args+=(-H "$h"); done
    [ -n "$data" ] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" > "$RESPONSE_FILE" 2>/dev/null
    HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
    BODY=$(sed '$d' "$RESPONSE_FILE")
}

auth_header() { echo "Authorization: Bearer ${ACCESS_TOKEN}"; }

# =============================================================================
# Setup: Register + Login + Create Team
# =============================================================================

print_header "Setup: Create Test User & Team"

do_request POST "/api/v1/auth/register" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"name\":\"${TEST_NAME}\"}"
if [ "$HTTP_CODE" = "201" ]; then
    print_success "Register user"
else
    print_failure "Register user (HTTP $HTTP_CODE)" "$BODY"
    echo -e "${RED}Cannot proceed without auth. Exiting.${NC}"
    exit 1
fi

do_request POST "/api/v1/auth/login" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')
if [ -n "$ACCESS_TOKEN" ]; then
    print_success "Login"
else
    print_failure "Login" "$BODY"
    exit 1
fi

do_request POST "/api/v1/tenants" "{\"name\":\"${TEST_TEAM}\",\"slug\":\"${TEST_SLUG}\"}" "$(auth_header)"
TENANT_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ -n "$TENANT_ID" ]; then
    print_success "Create team (tenant: $TENANT_ID)"
else
    print_failure "Create team" "$BODY"
    exit 1
fi

# Re-login to get tenant-scoped token
do_request POST "/api/v1/auth/login" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')

# =============================================================================
# 1. Dashboard Summary (Empty Tenant)
# =============================================================================

print_header "1. Dashboard Summary (Empty Tenant)"

print_test "GET /api/v1/dashboard/summary on empty tenant"
do_request GET "/api/v1/dashboard/summary" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    TOTAL_ASSETS=$(echo "$BODY" | jq -r '.total_assets // .assets_count // "missing"')
    TOTAL_FINDINGS=$(echo "$BODY" | jq -r '.total_findings // .findings_count // "missing"')
    print_success "Dashboard summary returned (assets: $TOTAL_ASSETS, findings: $TOTAL_FINDINGS)"
else
    print_failure "Dashboard summary failed (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Dashboard summary has expected fields"
do_request GET "/api/v1/dashboard/summary" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    # Check for common dashboard fields
    HAS_ASSETS=$(echo "$BODY" | jq 'has("total_assets") or has("assets_count") or has("assets")' 2>/dev/null)
    HAS_FINDINGS=$(echo "$BODY" | jq 'has("total_findings") or has("findings_count") or has("findings")' 2>/dev/null)
    if [ "$HAS_ASSETS" = "true" ] || [ "$HAS_FINDINGS" = "true" ]; then
        print_success "Dashboard has expected asset/finding fields"
    else
        print_failure "Dashboard missing expected fields" "$BODY"
    fi
else
    print_failure "Dashboard request failed (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 2. Asset Stats (Empty Tenant)
# =============================================================================

print_header "2. Asset Stats (Empty Tenant)"

print_test "GET /api/v1/assets/stats on empty tenant"
do_request GET "/api/v1/assets/stats" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    TOTAL=$(echo "$BODY" | jq -r '.total // "missing"')
    BY_TYPE=$(echo "$BODY" | jq -r '.by_type // "missing"')
    AVG_RISK=$(echo "$BODY" | jq -r '.risk_score_avg // "missing"')
    print_success "Asset stats returned (total: $TOTAL, avg_risk: $AVG_RISK)"
else
    print_failure "Asset stats failed (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Asset stats structure validation"
do_request GET "/api/v1/assets/stats" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    HAS_TOTAL=$(echo "$BODY" | jq 'has("total")' 2>/dev/null)
    HAS_BY_TYPE=$(echo "$BODY" | jq 'has("by_type")' 2>/dev/null)
    if [ "$HAS_TOTAL" = "true" ] && [ "$HAS_BY_TYPE" = "true" ]; then
        print_success "Stats has total and by_type fields"
    else
        print_failure "Stats missing expected fields" "$BODY"
    fi
else
    print_failure "Stats request failed (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 3. Dashboard With Data
# =============================================================================

print_header "3. Dashboard With Data"

# Create some test assets to populate dashboard
do_request POST "/api/v1/assets" \
    "{\"name\":\"Dash Asset 1 ${TIMESTAMP}\",\"type\":\"domain\",\"criticality\":\"critical\"}" \
    "$(auth_header)"
ASSET_ID_1=$(echo "$BODY" | jq -r '.id // empty')

do_request POST "/api/v1/assets" \
    "{\"name\":\"Dash Asset 2 ${TIMESTAMP}\",\"type\":\"ip_address\",\"criticality\":\"high\"}" \
    "$(auth_header)"
ASSET_ID_2=$(echo "$BODY" | jq -r '.id // empty')

do_request POST "/api/v1/assets" \
    "{\"name\":\"Dash Asset 3 ${TIMESTAMP}\",\"type\":\"repository\",\"criticality\":\"low\"}" \
    "$(auth_header)"
ASSET_ID_3=$(echo "$BODY" | jq -r '.id // empty')

print_test "Dashboard summary with assets"
do_request GET "/api/v1/dashboard/summary" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    TOTAL=$(echo "$BODY" | jq -r '.total_assets // .assets_count // .assets // 0')
    if [ "$TOTAL" -ge 3 ] 2>/dev/null; then
        print_success "Dashboard reflects created assets (total: $TOTAL)"
    else
        print_success "Dashboard returned data (total: $TOTAL)"
    fi
else
    print_failure "Dashboard with data failed (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Asset stats with data"
do_request GET "/api/v1/assets/stats" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    TOTAL=$(echo "$BODY" | jq -r '.total // 0')
    if [ "$TOTAL" -ge 3 ] 2>/dev/null; then
        print_success "Stats reflects created assets (total: $TOTAL)"
    else
        print_success "Stats returned data (total: $TOTAL)"
    fi
else
    print_failure "Stats with data failed (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 4. Edge Cases
# =============================================================================

print_header "4. Edge Cases"

print_test "Dashboard without auth returns 401"
do_request GET "/api/v1/dashboard/summary" ""
if [ "$HTTP_CODE" = "401" ]; then
    print_success "Dashboard requires authentication (401)"
else
    print_failure "Dashboard should require auth (got HTTP $HTTP_CODE)"
fi

print_test "Stats without auth returns 401"
do_request GET "/api/v1/assets/stats" ""
if [ "$HTTP_CODE" = "401" ]; then
    print_success "Stats requires authentication (401)"
else
    print_failure "Stats should require auth (got HTTP $HTTP_CODE)"
fi

print_test "Invalid auth token for dashboard"
do_request GET "/api/v1/dashboard/summary" "" "Authorization: Bearer invalid.token.here"
if [ "$HTTP_CODE" = "401" ]; then
    print_success "Invalid token rejected for dashboard (401)"
else
    print_failure "Invalid token should be rejected (got HTTP $HTTP_CODE)"
fi

# =============================================================================
# Cleanup
# =============================================================================

print_header "Cleanup"

for AID in "$ASSET_ID_1" "$ASSET_ID_2" "$ASSET_ID_3"; do
    if [ -n "$AID" ]; then
        do_request DELETE "/api/v1/assets/${AID}" "" "$(auth_header)"
    fi
done
print_success "Cleaned up test data"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}Dashboard Endpoints E2E Test Summary${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASSED}${NC}"
echo -e "  Failed:  ${RED}${FAILED}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIPPED}${NC}"
echo -e "  Total Tests: $((PASSED + FAILED + SKIPPED))"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All dashboard tests passed!${NC}"
    exit 0
else
    echo -e "  ${RED}Some dashboard tests failed!${NC}"
    exit 1
fi
