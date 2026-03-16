#!/bin/bash
# =============================================================================
# End-to-End Tools Registry Test Script
# =============================================================================
# Tests tools lifecycle:
#   Register -> Login -> Create Team -> Tool CRUD -> Categories
#   -> Capabilities -> Tenant Tool Config -> Stats -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#
# Usage:
#   ./test_e2e_tools_registry.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-tools-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Tools User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Tools Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-tools-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
TOOL_ID=""
TOOL_NAME=""
CATEGORY_ID=""
CRITICAL_FAILURE=0

BODY=""
HTTP_CODE=""

print_header() {
    echo -e "\n${BLUE}==============================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

print_test() { echo -e "\n${YELLOW}>>> Test: $1${NC}"; }
print_success() { echo -e "${GREEN}  PASSED: $1${NC}"; PASSED=$((PASSED + 1)); }
print_failure() { echo -e "${RED}  FAILED: $1${NC}"; [ -n "$2" ] && echo -e "${RED}  Error: $2${NC}"; FAILED=$((FAILED + 1)); }
print_skip() { echo -e "${YELLOW}  SKIPPED: $1${NC}"; SKIPPED=$((SKIPPED + 1)); }
print_info() { echo -e "  $1"; }
extract_json() { echo "$1" | jq -r "$2" 2>/dev/null; }

do_request() {
    local method="$1" endpoint="$2" data="$3"
    shift 3
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json" -c "$COOKIE_JAR" -b "$COOKIE_JAR")
    for header in "$@"; do curl_args+=(-H "$header"); done
    [ -n "$data" ] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" > "$RESPONSE_FILE" 2>/dev/null
    HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
    BODY=$(sed '$d' "$RESPONSE_FILE")
}

check_critical() { [ "$CRITICAL_FAILURE" -eq 1 ] && { print_skip "$1 (skipped due to earlier critical failure)"; return 1; }; return 0; }
mark_critical_failure() { CRITICAL_FAILURE=1; }

# =============================================================================
print_header "E2E Tools Registry Test Suite"
echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

for cmd in jq curl; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: $cmd is required but not installed.${NC}"
        exit 1
    fi
done

# =============================================================================
# Section 1: Health Check
# =============================================================================
print_header "Section 1: Health Check"
print_test "API Health Check"
do_request "GET" "/health" ""
if [ "$HTTP_CODE" = "200" ]; then print_success "API is healthy"; else print_failure "Health check" "Expected 200, got $HTTP_CODE"; exit 1; fi

# =============================================================================
# Section 2: Auth Flow
# =============================================================================
print_header "Section 2: Authentication"

print_test "Register new user"
do_request "POST" "/api/v1/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"name\":\"$TEST_NAME\"}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then print_success "User registered"
elif [ "$HTTP_CODE" = "409" ]; then print_success "Registration handled (user exists)"
elif [ "$HTTP_CODE" = "429" ]; then print_failure "Rate limited" "Wait and try again"; mark_critical_failure
else print_failure "Registration" "Expected 201, got $HTTP_CODE"; mark_critical_failure; fi

if ! check_critical "Login"; then :; else
print_test "Login"
do_request "POST" "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
if [ "$HTTP_CODE" = "200" ]; then print_success "Logged in"; else print_failure "Login" "Expected 200, got $HTTP_CODE"; mark_critical_failure; fi
fi

if ! check_critical "Create Team"; then :; else
print_test "Create first team"
do_request "POST" "/api/v1/auth/create-first-team" "{\"team_name\":\"$TEST_TEAM_NAME\",\"team_slug\":\"$TEST_TEAM_SLUG\"}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] && print_success "Team created" || { print_failure "Create team" "Missing access_token"; mark_critical_failure; }
elif [ "$HTTP_CODE" = "409" ]; then
    do_request "POST" "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    FIRST_TENANT_ID=$(extract_json "$BODY" '.tenants[0].id')
    if [ -n "$FIRST_TENANT_ID" ] && [ "$FIRST_TENANT_ID" != "null" ]; then
        do_request "POST" "/api/v1/auth/token" "{\"refresh_token\":\"$REFRESH_TOKEN\",\"tenant_id\":\"$FIRST_TENANT_ID\"}"
        [ "$HTTP_CODE" = "200" ] && { ACCESS_TOKEN=$(extract_json "$BODY" '.access_token'); TENANT_ID="$FIRST_TENANT_ID"; print_success "Token exchanged"; } || { print_failure "Token exchange"; mark_critical_failure; }
    else print_failure "No tenants found"; mark_critical_failure; fi
else print_failure "Create team" "Expected 201, got $HTTP_CODE"; mark_critical_failure; fi
fi

# =============================================================================
# Section 3: Create Tool
# =============================================================================
print_header "Section 3: Create Tool"

if ! check_critical "Create Tool"; then :; else
TOOL_NAME="e2e-nmap-${TIMESTAMP}"
print_test "Create tool"
do_request "POST" "/api/v1/tools" "{
    \"name\": \"$TOOL_NAME\",
    \"display_name\": \"E2E Nmap ${TIMESTAMP}\",
    \"description\": \"E2E test tool for network scanning\",
    \"install_method\": \"binary\",
    \"capabilities\": [\"port_scan\"],
    \"supported_targets\": [\"ip\", \"domain\"],
    \"tags\": [\"e2e-test\", \"scanner\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    TOOL_ID=$(extract_json "$BODY" '.id')
    print_info "Tool ID: $TOOL_ID"
    print_success "Tool created"
else
    print_failure "Create tool" "Expected 201, got $HTTP_CODE"
    print_info "Response: $(echo "$BODY" | head -c 200)"
fi
fi

# =============================================================================
# Section 4: List & Get Tools
# =============================================================================
print_header "Section 4: List & Get Tools"

if ! check_critical "List Tools"; then :; else

print_test "List tools"
do_request "GET" "/api/v1/tools" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    TOOL_COUNT=$(extract_json "$BODY" '.total // (.data | length) // 0')
    print_info "Total tools: $TOOL_COUNT"
    print_success "Tools listed"
else
    print_failure "List tools" "Expected 200, got $HTTP_CODE"
fi

print_test "Get tool by ID"
if [ -n "$TOOL_ID" ] && [ "$TOOL_ID" != "null" ]; then
    do_request "GET" "/api/v1/tools/$TOOL_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get tool by ID"
    else
        print_failure "Get tool" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get tool (no ID)"
fi

print_test "Get tool by name"
if [ -n "$TOOL_NAME" ]; then
    do_request "GET" "/api/v1/tools/name/$TOOL_NAME" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get tool by name"
    else
        print_failure "Get tool by name" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get tool by name (no name)"
fi

fi

# =============================================================================
# Section 5: Update Tool
# =============================================================================
print_header "Section 5: Update Tool"

if ! check_critical "Update Tool"; then :; else

print_test "Update tool"
if [ -n "$TOOL_ID" ] && [ "$TOOL_ID" != "null" ]; then
    do_request "PUT" "/api/v1/tools/$TOOL_ID" "{
        \"display_name\": \"Updated E2E Nmap ${TIMESTAMP}\",
        \"description\": \"Updated by E2E test\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Tool updated"
    else
        print_failure "Update tool" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Update tool (no ID)"
fi

fi

# =============================================================================
# Section 6: Activate/Deactivate Tool
# =============================================================================
print_header "Section 6: Activate/Deactivate Tool"

if ! check_critical "Tool Lifecycle"; then :; else

print_test "Deactivate tool"
if [ -n "$TOOL_ID" ] && [ "$TOOL_ID" != "null" ]; then
    do_request "POST" "/api/v1/tools/$TOOL_ID/deactivate" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Tool deactivated"
    else
        print_failure "Deactivate tool" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Deactivate tool (no ID)"
fi

print_test "Activate tool"
if [ -n "$TOOL_ID" ] && [ "$TOOL_ID" != "null" ]; then
    do_request "POST" "/api/v1/tools/$TOOL_ID/activate" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Tool activated"
    else
        print_failure "Activate tool" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Activate tool (no ID)"
fi

fi

# =============================================================================
# Section 7: Platform Tools & Categories
# =============================================================================
print_header "Section 7: Platform Tools & Categories"

if ! check_critical "Platform Tools"; then :; else

print_test "List platform tools"
do_request "GET" "/api/v1/tools/platform" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Platform tools listed"
else
    print_failure "List platform tools" "Expected 200, got $HTTP_CODE"
fi

print_test "List all tool categories"
do_request "GET" "/api/v1/tool-categories/all" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Tool categories listed"
else
    print_failure "List categories" "Expected 200, got $HTTP_CODE"
fi

print_test "Create custom tool category"
do_request "POST" "/api/v1/custom-tool-categories" "{
    \"name\": \"e2e-cat-${TIMESTAMP}\",
    \"display_name\": \"E2E Category ${TIMESTAMP}\",
    \"description\": \"E2E test category\"
}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    CATEGORY_ID=$(extract_json "$BODY" '.id')
    print_info "Category ID: $CATEGORY_ID"
    print_success "Custom category created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create category" "Expected 201, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Capabilities
# =============================================================================
print_header "Section 8: Capabilities"

if ! check_critical "Capabilities"; then :; else

print_test "List all capabilities"
do_request "GET" "/api/v1/capabilities/all" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "All capabilities listed"
else
    print_failure "List capabilities" "Expected 200, got $HTTP_CODE"
fi

print_test "Get capability categories"
do_request "GET" "/api/v1/capabilities/categories" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Capability categories retrieved"
else
    print_failure "Capability categories" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 9: Tenant Tools & Stats
# =============================================================================
print_header "Section 9: Tenant Tools & Stats"

if ! check_critical "Tenant Tools"; then :; else

print_test "List all tenant tools"
do_request "GET" "/api/v1/tenant-tools/all-tools" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "All tenant tools listed"
else
    print_failure "List tenant tools" "Expected 200, got $HTTP_CODE"
fi

print_test "Get tool stats"
do_request "GET" "/api/v1/tool-stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Tool stats retrieved"
else
    print_failure "Tool stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 10: Delete Tool
# =============================================================================
print_header "Section 10: Delete Tool"

if ! check_critical "Delete Tool"; then :; else

print_test "Delete tool"
if [ -n "$TOOL_ID" ] && [ "$TOOL_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/tools/$TOOL_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Tool deleted"
    elif [ "$HTTP_CODE" = "403" ]; then
        print_success "Tool delete handled (requires tools:delete permission)"
    else
        print_failure "Delete tool" "Expected 200/204, got $HTTP_CODE"
    fi
else
    print_skip "Delete tool (no ID)"
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
        ERROR_COUNT=0
        [ -n "$ERROR_LINES" ] && ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
        print_info "Panics: $PANIC_COUNT | Fatals: $FATAL_COUNT | Errors: $ERROR_COUNT"
        if [ "$PANIC_COUNT" -gt 0 ]; then print_failure "Docker logs: panics detected"
        elif [ "$FATAL_COUNT" -gt 0 ]; then print_failure "Docker logs: fatals detected"
        elif [ "$ERROR_COUNT" -gt 10 ]; then print_failure "Docker logs: >10 errors"
        else print_success "Docker logs clean"; fi
    else print_skip "Docker log check (no API container)"; fi
else print_skip "Docker log check (docker not available)"; fi

# =============================================================================
print_header "Test Summary"
TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  Total Tests: $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
[ "$SKIPPED" -gt 0 ] && echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
echo ""
if [ "$FAILED" -eq 0 ]; then echo -e "  ${GREEN}All tests passed!${NC}"; echo ""; exit 0
else echo -e "  ${RED}Some tests failed.${NC}"; echo ""; exit 1; fi
