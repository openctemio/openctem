#!/bin/bash
# =============================================================================
# End-to-End Scan Management Test Script
# =============================================================================
# Tests the scan lifecycle:
#   Register -> Login -> Create Team -> Create Asset Group -> Scan Profiles
#   -> Scan CRUD -> Pipelines -> Stats -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_scans.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_scans.sh
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
TEST_EMAIL="e2e-scans-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Scan User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Scan Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-scan-${TIMESTAMP}"

# Temp files
COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Extracted values
ACCESS_TOKEN=""
TENANT_ID=""
ASSET_ID=""
ASSET_GROUP_ID=""
SCAN_PROFILE_ID=""
SCAN_ID=""
PIPELINE_ID=""
CRITICAL_FAILURE=0

# Global response variables
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

print_header "E2E Scan Management Test Suite"

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
if [ "$HTTP_CODE" = "200" ]; then
    print_success "API is healthy"
else
    print_failure "API health check" "Expected 200, got $HTTP_CODE"
    exit 1
fi

# =============================================================================
# Section 2: Auth Flow
# =============================================================================

print_header "Section 2: Authentication"

print_test "Register new user"
do_request "POST" "/api/v1/auth/register" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\",
    \"name\": \"$TEST_NAME\"
}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "User registered"
elif [ "$HTTP_CODE" = "409" ]; then
    print_success "Registration handled (user exists)"
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
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        print_success "First team created"
    else
        print_failure "Create first team" "Missing access_token"
        mark_critical_failure
    fi
elif [ "$HTTP_CODE" = "409" ]; then
    do_request "POST" "/api/v1/auth/login" "{\"email\": \"$TEST_EMAIL\", \"password\": \"$TEST_PASSWORD\"}"
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    FIRST_TENANT_ID=$(extract_json "$BODY" '.tenants[0].id')
    if [ -n "$FIRST_TENANT_ID" ] && [ "$FIRST_TENANT_ID" != "null" ]; then
        do_request "POST" "/api/v1/auth/token" "{\"refresh_token\": \"$REFRESH_TOKEN\", \"tenant_id\": \"$FIRST_TENANT_ID\"}"
        if [ "$HTTP_CODE" = "200" ]; then
            ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
            TENANT_ID="$FIRST_TENANT_ID"
            print_success "Token exchanged for existing team"
        else
            print_failure "Token exchange" "Expected 200, got $HTTP_CODE"
            mark_critical_failure
        fi
    else
        print_failure "No tenants found" ""
        mark_critical_failure
    fi
else
    print_failure "Create first team" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi
fi

# =============================================================================
# Section 3: Prerequisites (Asset + Asset Group)
# =============================================================================

print_header "Section 3: Prerequisites"

if ! check_critical "Create Asset"; then :; else

print_test "Create asset"
do_request "POST" "/api/v1/assets" "{
    \"name\": \"e2e-scan-target-${TIMESTAMP}.example.com\",
    \"type\": \"domain\",
    \"criticality\": \"high\"
}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_ID=$(extract_json "$BODY" '.id')
    print_info "Asset ID: $ASSET_ID"
    print_success "Asset created"
else
    print_failure "Create asset" "Expected 201, got $HTTP_CODE"
fi

print_test "Create asset group"
do_request "POST" "/api/v1/asset-groups" "{
    \"name\": \"E2E Scan Group ${TIMESTAMP}\",
    \"environment\": \"testing\",
    \"criticality\": \"high\",
    \"existing_asset_ids\": [\"$ASSET_ID\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_GROUP_ID=$(extract_json "$BODY" '.id')
    print_info "Asset Group ID: $ASSET_GROUP_ID"
    print_success "Asset group created"
else
    print_failure "Create asset group" "Expected 201, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: Scan Profiles
# =============================================================================

print_header "Section 4: Scan Profiles"

if ! check_critical "Scan Profiles"; then :; else

print_test "Create scan profile"
do_request "POST" "/api/v1/scan-profiles" "{
    \"name\": \"E2E Profile ${TIMESTAMP}\",
    \"description\": \"E2E test scan profile\",
    \"intensity\": \"medium\",
    \"max_concurrent_scans\": 2,
    \"timeout_seconds\": 3600,
    \"tags\": [\"e2e-test\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SCAN_PROFILE_ID=$(extract_json "$BODY" '.id')
    print_info "Scan Profile ID: $SCAN_PROFILE_ID"
    print_success "Scan profile created"
else
    print_failure "Create scan profile" "Expected 201, got $HTTP_CODE"
fi

print_test "List scan profiles"
do_request "GET" "/api/v1/scan-profiles" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "List scan profiles"
else
    print_failure "List scan profiles" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 5: Scan CRUD
# =============================================================================

print_header "Section 5: Scan CRUD"

if ! check_critical "Scan CRUD"; then :; else

# Create a tool first (required for single scan type)
print_test "Create tool for scan"
do_request "POST" "/api/v1/tools" "{
    \"name\": \"e2e-nmap-${TIMESTAMP}\",
    \"display_name\": \"E2E Nmap ${TIMESTAMP}\",
    \"description\": \"E2E test tool\",
    \"install_method\": \"binary\",
    \"capabilities\": [\"port_scan\"],
    \"supported_targets\": [\"ip\", \"domain\"]
}" "Authorization: Bearer $ACCESS_TOKEN"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    TOOL_NAME="e2e-nmap-${TIMESTAMP}"
    print_success "Tool created for scan"
else
    print_failure "Create tool for scan" "Expected 201, got $HTTP_CODE"
    TOOL_NAME=""
fi

print_test "Create scan"
SCAN_DATA="{
    \"name\": \"E2E Scan ${TIMESTAMP}\",
    \"description\": \"E2E test scan\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"${TOOL_NAME}\",
    \"schedule_type\": \"manual\"
}"
# Add asset_group_id if available
if [ -n "$ASSET_GROUP_ID" ] && [ "$ASSET_GROUP_ID" != "null" ]; then
    SCAN_DATA="{
        \"name\": \"E2E Scan ${TIMESTAMP}\",
        \"description\": \"E2E test scan\",
        \"scan_type\": \"single\",
        \"scanner_name\": \"${TOOL_NAME}\",
        \"asset_group_id\": \"$ASSET_GROUP_ID\",
        \"schedule_type\": \"manual\"
    }"
fi
do_request "POST" "/api/v1/scans" "$SCAN_DATA" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SCAN_ID=$(extract_json "$BODY" '.id')
    print_info "Scan ID: $SCAN_ID"
    print_success "Scan created"
else
    print_failure "Create scan" "Expected 201, got $HTTP_CODE"
fi

print_test "List scans"
do_request "GET" "/api/v1/scans" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    SCAN_TOTAL=$(extract_json "$BODY" '.total // .pagination.total // 0')
    print_info "Total scans: $SCAN_TOTAL"
    print_success "List scans"
else
    print_failure "List scans" "Expected 200, got $HTTP_CODE"
fi

print_test "Get single scan"
if [ -n "$SCAN_ID" ] && [ "$SCAN_ID" != "null" ]; then
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get scan by ID"
    else
        print_failure "Get scan" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get scan (no scan ID)"
fi

print_test "Update scan"
if [ -n "$SCAN_ID" ] && [ "$SCAN_ID" != "null" ]; then
    do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
        \"name\": \"E2E Scan Updated ${TIMESTAMP}\",
        \"description\": \"Updated by E2E test\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Scan updated"
    else
        print_failure "Update scan" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Update scan (no scan ID)"
fi

fi

# =============================================================================
# Section 6: Scan Status Operations
# =============================================================================

print_header "Section 6: Scan Status Operations"

if ! check_critical "Scan Status"; then :; else

if [ -n "$SCAN_ID" ] && [ "$SCAN_ID" != "null" ]; then
    print_test "Activate scan"
    do_request "POST" "/api/v1/scans/$SCAN_ID/activate" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Scan activated"
    else
        print_failure "Activate scan" "Expected 200, got $HTTP_CODE"
    fi

    print_test "Pause scan"
    do_request "POST" "/api/v1/scans/$SCAN_ID/pause" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Scan paused"
    else
        print_failure "Pause scan" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Activate scan (no scan ID)"
    print_skip "Pause scan (no scan ID)"
fi

fi

# =============================================================================
# Section 7: Scan Stats
# =============================================================================

print_header "Section 7: Scan Stats"

if ! check_critical "Scan Stats"; then :; else

print_test "Get scan stats"
do_request "GET" "/api/v1/scans/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Scan stats retrieved"
else
    print_failure "Scan stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Pipelines
# =============================================================================

print_header "Section 8: Pipelines"

if ! check_critical "Pipelines"; then :; else

print_test "Create pipeline"
do_request "POST" "/api/v1/pipelines" "{
    \"name\": \"E2E Pipeline ${TIMESTAMP}\",
    \"description\": \"E2E test pipeline\",
    \"tags\": [\"e2e-test\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    PIPELINE_ID=$(extract_json "$BODY" '.id')
    print_info "Pipeline ID: $PIPELINE_ID"
    print_success "Pipeline created"
else
    print_failure "Create pipeline" "Expected 201, got $HTTP_CODE"
fi

print_test "List pipelines"
do_request "GET" "/api/v1/pipelines" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "List pipelines"
else
    print_failure "List pipelines" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 9: Delete Scan
# =============================================================================

print_header "Section 9: Delete Scan"

if ! check_critical "Delete Scan"; then :; else

print_test "Delete scan"
if [ -n "$SCAN_ID" ] && [ "$SCAN_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/scans/$SCAN_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Scan deleted"
    else
        print_failure "Delete scan" "Expected 200/204, got $HTTP_CODE"
    fi
else
    print_skip "Delete scan (no scan ID)"
fi

fi

# =============================================================================
# Section 10: Docker Log Check
# =============================================================================

print_header "Section 10: Docker Log Check"

print_test "Check Docker logs for errors"
if command -v docker &> /dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)
    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=$(echo "$ERROR_LINES" | grep -c "." 2>/dev/null || true)
        if [ -z "$ERROR_LINES" ]; then ERROR_COUNT=0; fi

        print_info "Panics: $PANIC_COUNT | Fatals: $FATAL_COUNT | Errors: $ERROR_COUNT"

        if [ "$PANIC_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $PANIC_COUNT panic(s)"
        elif [ "$FATAL_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $FATAL_COUNT fatal(s)"
        elif [ "$ERROR_COUNT" -gt 10 ]; then
            print_failure "Docker logs: $ERROR_COUNT error(s) (>10 threshold)"
        else
            print_success "Docker logs clean"
        fi
    else
        print_skip "Docker log check (no API container)"
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
