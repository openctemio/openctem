#!/bin/bash
# =============================================================================
# End-to-End Asset Management Test Script
# =============================================================================
# Tests the full asset lifecycle:
#   Register -> Login -> Create Team -> Create Asset -> Asset Groups
#   -> Relationships -> Components -> Stats -> Delete -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_assets.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_assets.sh
# =============================================================================

# Don't use set -e because counter arithmetic can return 1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-assets-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Asset User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Asset Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-asset-${TIMESTAMP}"

# Temp files
COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Extracted values (populated during tests)
ACCESS_TOKEN=""
TENANT_ID=""
AGENT_ID=""
API_KEY=""
ASSET_ID=""
ASSET_ID_2=""
ASSET_GROUP_ID=""
COMPONENT_ID=""
CRITICAL_FAILURE=0

# Global response variables (set by do_request)
BODY=""
HTTP_CODE=""

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo -e "\n${BLUE}==============================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

print_test() {
    echo -e "\n${YELLOW}>>> Test: $1${NC}"
}

print_success() {
    echo -e "${GREEN}  PASSED: $1${NC}"
    PASSED=$((PASSED + 1))
}

print_failure() {
    echo -e "${RED}  FAILED: $1${NC}"
    if [ -n "$2" ]; then
        echo -e "${RED}  Error: $2${NC}"
    fi
    FAILED=$((FAILED + 1))
}

print_skip() {
    echo -e "${YELLOW}  SKIPPED: $1${NC}"
    SKIPPED=$((SKIPPED + 1))
}

print_info() {
    echo -e "  $1"
}

extract_json() {
    echo "$1" | jq -r "$2" 2>/dev/null
}

do_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    shift 3

    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json"
        -c "$COOKIE_JAR" -b "$COOKIE_JAR")

    for header in "$@"; do
        curl_args+=(-H "$header")
    done

    if [ -n "$data" ]; then
        curl_args+=(-d "$data")
    fi

    curl "${curl_args[@]}" > "$RESPONSE_FILE" 2>/dev/null
    HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
    BODY=$(sed '$d' "$RESPONSE_FILE")
}

check_critical() {
    if [ "$CRITICAL_FAILURE" -eq 1 ]; then
        print_skip "$1 (skipped due to earlier critical failure)"
        return 1
    fi
    return 0
}

mark_critical_failure() {
    CRITICAL_FAILURE=1
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

print_header "E2E Asset Management Test Suite"

echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required but not installed.${NC}"
    exit 1
fi

# =============================================================================
# Section 1: Health Check
# =============================================================================

print_header "Section 1: Health Check"

print_test "API Health Check"
do_request "GET" "/health" ""
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "API is healthy"
else
    print_failure "API health check" "Expected 200, got $HTTP_CODE"
    echo -e "${RED}Cannot continue without a healthy API. Aborting.${NC}"
    exit 1
fi

# =============================================================================
# Section 2: Auth Flow (Register + Login + Create Team)
# =============================================================================

print_header "Section 2: Authentication"

print_test "Register new user"
do_request "POST" "/api/v1/auth/register" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\",
    \"name\": \"$TEST_NAME\"
}"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "User registered"
elif [ "$HTTP_CODE" = "409" ]; then
    print_success "Registration handled (user exists)"
elif [ "$HTTP_CODE" = "429" ]; then
    print_failure "Registration rate limited" "Wait and try again"
    mark_critical_failure
else
    print_failure "User registration" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

if ! check_critical "Login"; then :; else

print_test "Login"
do_request "POST" "/api/v1/auth/login" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
}"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "User logged in"
else
    print_failure "User login" "Expected 200, got $HTTP_CODE"
    mark_critical_failure
fi

fi

if ! check_critical "Create Team"; then :; else

print_test "Create first team"
do_request "POST" "/api/v1/auth/create-first-team" "{
    \"team_name\": \"$TEST_TEAM_NAME\",
    \"team_slug\": \"$TEST_TEAM_SLUG\"
}"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        print_info "Tenant ID: $TENANT_ID"
        print_success "First team created"
    else
        print_failure "Create first team" "Missing access_token"
        mark_critical_failure
    fi
elif [ "$HTTP_CODE" = "409" ]; then
    print_info "User already has a team, exchanging token..."
    do_request "POST" "/api/v1/auth/login" "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }"
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    FIRST_TENANT_ID=$(extract_json "$BODY" '.tenants[0].id')
    if [ -n "$FIRST_TENANT_ID" ] && [ "$FIRST_TENANT_ID" != "null" ]; then
        do_request "POST" "/api/v1/auth/token" "{
            \"refresh_token\": \"$REFRESH_TOKEN\",
            \"tenant_id\": \"$FIRST_TENANT_ID\"
        }"
        if [ "$HTTP_CODE" = "200" ]; then
            ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
            TENANT_ID="$FIRST_TENANT_ID"
            print_success "Token exchanged for existing team"
        else
            print_failure "Token exchange" "Expected 200, got $HTTP_CODE"
            mark_critical_failure
        fi
    else
        print_failure "Create first team" "No tenants found"
        mark_critical_failure
    fi
else
    print_failure "Create first team" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

fi

# =============================================================================
# Section 3: Create Asset
# =============================================================================

print_header "Section 3: Create Asset"

if ! check_critical "Create Asset"; then :; else

print_test "Create a domain asset"
do_request "POST" "/api/v1/assets" "{
    \"name\": \"e2e-domain-${TIMESTAMP}.example.com\",
    \"type\": \"domain\",
    \"criticality\": \"high\",
    \"description\": \"E2E test domain asset\",
    \"tags\": [\"e2e-test\", \"automated\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_ID=$(extract_json "$BODY" '.id')
    if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
        print_info "Asset ID: $ASSET_ID"
        print_success "Domain asset created"
    else
        print_failure "Create asset" "Missing id in response"
        mark_critical_failure
    fi
else
    print_failure "Create asset" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

fi

# Create a second asset for relationship testing
if ! check_critical "Create second asset"; then :; else

print_test "Create a second asset (website)"
do_request "POST" "/api/v1/assets" "{
    \"name\": \"e2e-webapp-${TIMESTAMP}.example.com\",
    \"type\": \"website\",
    \"criticality\": \"medium\",
    \"description\": \"E2E test website asset\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_ID_2=$(extract_json "$BODY" '.id')
    print_info "Asset ID 2: $ASSET_ID_2"
    print_success "Website asset created"
else
    print_failure "Create second asset" "Expected 201, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: List & Get Assets
# =============================================================================

print_header "Section 4: List & Get Assets"

if ! check_critical "List Assets"; then :; else

print_test "List assets"
do_request "GET" "/api/v1/assets" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    TOTAL=$(extract_json "$BODY" '.total // .pagination.total // 0')
    print_info "Total assets: $TOTAL"
    if [ "$TOTAL" -ge 1 ] 2>/dev/null; then
        print_success "List assets (total >= 1)"
    else
        print_success "List assets (returned 200)"
    fi
else
    print_failure "List assets" "Expected 200, got $HTTP_CODE"
fi

print_test "Get single asset"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "GET" "/api/v1/assets/$ASSET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        ASSET_NAME=$(extract_json "$BODY" '.name')
        print_info "Asset name: $ASSET_NAME"
        print_success "Get asset by ID"
    else
        print_failure "Get asset" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get asset (no asset ID)"
fi

fi

# =============================================================================
# Section 5: Update Asset
# =============================================================================

print_header "Section 5: Update Asset"

if ! check_critical "Update Asset"; then :; else

print_test "Update asset criticality"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "PUT" "/api/v1/assets/$ASSET_ID" "{
        \"criticality\": \"medium\",
        \"description\": \"Updated by E2E test\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        UPDATED_CRIT=$(extract_json "$BODY" '.criticality')
        print_info "Updated criticality: $UPDATED_CRIT"
        print_success "Asset updated"
    else
        print_failure "Update asset" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Update asset (no asset ID)"
fi

fi

# =============================================================================
# Section 6: Asset Stats
# =============================================================================

print_header "Section 6: Asset Stats"

if ! check_critical "Asset Stats"; then :; else

print_test "Get asset stats"
do_request "GET" "/api/v1/assets/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Asset stats retrieved"
else
    print_failure "Asset stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 7: Asset Groups
# =============================================================================

print_header "Section 7: Asset Groups"

if ! check_critical "Asset Groups"; then :; else

print_test "Create asset group"
do_request "POST" "/api/v1/asset-groups" "{
    \"name\": \"E2E Test Group ${TIMESTAMP}\",
    \"description\": \"E2E test asset group\",
    \"environment\": \"production\",
    \"criticality\": \"high\",
    \"business_unit\": \"Engineering\",
    \"tags\": [\"e2e-test\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_GROUP_ID=$(extract_json "$BODY" '.id')
    print_info "Asset Group ID: $ASSET_GROUP_ID"
    print_success "Asset group created"
else
    print_failure "Create asset group" "Expected 201, got $HTTP_CODE"
fi

print_test "List asset groups"
do_request "GET" "/api/v1/asset-groups" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    AG_TOTAL=$(extract_json "$BODY" '.total // .pagination.total // 0')
    print_info "Total groups: $AG_TOTAL"
    print_success "List asset groups"
else
    print_failure "List asset groups" "Expected 200, got $HTTP_CODE"
fi

# Add assets to group
print_test "Add assets to group"
if [ -n "$ASSET_GROUP_ID" ] && [ "$ASSET_GROUP_ID" != "null" ] && [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "POST" "/api/v1/asset-groups/$ASSET_GROUP_ID/assets" "{
        \"asset_ids\": [\"$ASSET_ID\"]
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Assets added to group"
    else
        print_failure "Add assets to group" "Expected 200/201/204, got $HTTP_CODE"
    fi
else
    print_skip "Add assets to group (missing IDs)"
fi

# Get group assets
print_test "Get group assets"
if [ -n "$ASSET_GROUP_ID" ] && [ "$ASSET_GROUP_ID" != "null" ]; then
    do_request "GET" "/api/v1/asset-groups/$ASSET_GROUP_ID/assets" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get group assets"
    else
        print_failure "Get group assets" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get group assets (no group ID)"
fi

fi

# =============================================================================
# Section 8: Asset Relationships
# =============================================================================

print_header "Section 8: Asset Relationships"

if ! check_critical "Asset Relationships"; then :; else

print_test "Create asset relationship"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ] && [ -n "$ASSET_ID_2" ] && [ "$ASSET_ID_2" != "null" ]; then
    do_request "POST" "/api/v1/assets/$ASSET_ID/relationships" "{
        \"type\": \"depends_on\",
        \"source_asset_id\": \"$ASSET_ID_2\",
        \"target_asset_id\": \"$ASSET_ID\",
        \"description\": \"Website depends on domain\",
        \"confidence\": \"high\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    print_info "Response: $(echo "$BODY" | head -c 300)"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Relationship created"
    else
        print_failure "Create relationship" "Expected 201, got $HTTP_CODE"
    fi
else
    print_skip "Create relationship (missing asset IDs)"
fi

print_test "List asset relationships"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "GET" "/api/v1/assets/$ASSET_ID/relationships" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        print_success "List relationships"
    else
        print_failure "List relationships" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "List relationships (no asset ID)"
fi

fi

# =============================================================================
# Section 9: Components
# =============================================================================

print_header "Section 9: Components"

if ! check_critical "Components"; then :; else

print_test "Create component"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "POST" "/api/v1/components" "{
        \"asset_id\": \"$ASSET_ID\",
        \"name\": \"lodash\",
        \"version\": \"4.17.21\",
        \"ecosystem\": \"npm\",
        \"package_manager\": \"npm\",
        \"license\": \"MIT\",
        \"manifest_file\": \"package.json\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    print_info "Response: $(echo "$BODY" | head -c 300)"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        COMPONENT_ID=$(extract_json "$BODY" '.id')
        print_info "Component ID: $COMPONENT_ID"
        print_success "Component created"
    else
        print_failure "Create component" "Expected 201, got $HTTP_CODE"
    fi
else
    print_skip "Create component (no asset ID)"
fi

print_test "List components"
do_request "GET" "/api/v1/components" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "List components"
else
    print_failure "List components" "Expected 200, got $HTTP_CODE"
fi

print_test "Get component stats"
do_request "GET" "/api/v1/components/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Component stats retrieved"
else
    print_failure "Component stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 10: Delete Asset
# =============================================================================

print_header "Section 10: Delete Asset"

if ! check_critical "Delete Asset"; then :; else

print_test "Delete asset"
if [ -n "$ASSET_ID_2" ] && [ "$ASSET_ID_2" != "null" ]; then
    do_request "DELETE" "/api/v1/assets/$ASSET_ID_2" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Asset deleted"
    else
        print_failure "Delete asset" "Expected 200/204, got $HTTP_CODE"
    fi
else
    print_skip "Delete asset (no asset ID)"
fi

fi

# =============================================================================
# Section 11: Docker Log Check
# =============================================================================

print_header "Section 11: Docker Log Check"

print_test "Check Docker logs for errors"
if command -v docker &> /dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)
    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=$(echo "$ERROR_LINES" | grep -c "." 2>/dev/null || true)
        if [ -z "$ERROR_LINES" ]; then
            ERROR_COUNT=0
        fi

        print_info "Panics (last 2m): $PANIC_COUNT"
        print_info "Fatals (last 2m): $FATAL_COUNT"
        print_info "Error logs (last 2m): $ERROR_COUNT"

        if [ "$PANIC_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $PANIC_COUNT panic(s) detected"
        elif [ "$FATAL_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $FATAL_COUNT fatal(s) detected"
        elif [ "$ERROR_COUNT" -gt 10 ]; then
            print_failure "Docker logs: $ERROR_COUNT error(s) (>10 threshold)"
        else
            print_success "Docker logs clean"
        fi
    else
        print_skip "Docker log check (no API container found)"
    fi
else
    print_skip "Docker log check (docker not available)"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Test Summary"

TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  Total Tests: $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
if [ "$SKIPPED" -gt 0 ]; then
    echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All tests passed!${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}Some tests failed. Review the output above for details.${NC}"
    echo ""
    exit 1
fi
