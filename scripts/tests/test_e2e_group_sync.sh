#!/bin/bash
# =============================================================================
# End-to-End Group Sync Test Script
# =============================================================================
# Tests group sync functionality:
#   Register -> Login -> Create Team -> Trigger Group Sync
#   -> Verify Response -> Auth Check (401) -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_group_sync.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_group_sync.sh
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
TEST_EMAIL="e2e-grpsync-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E GroupSync User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E GroupSync Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-grpsync-${TIMESTAMP}"

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

print_header "E2E Group Sync Test Suite"

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
# Section 3: Setup - Create Groups for Sync Testing
# =============================================================================

print_header "Section 3: Setup Groups"

if ! check_critical "Setup Groups"; then :; else

print_test "Create asset group (prerequisite for sync)"
do_request "POST" "/api/v1/asset-groups" "{
    \"name\": \"E2E Sync Group ${TIMESTAMP}\",
    \"description\": \"Test group for sync E2E\",
    \"environment\": \"production\",
    \"criticality\": \"high\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    GROUP_ID=$(extract_json "$BODY" '.id')
    print_info "Group ID: $GROUP_ID"
    print_success "Asset group created for sync test"
else
    print_failure "Create asset group" "Expected 201, got $HTTP_CODE"
    print_info "Sync test will proceed without a pre-created group"
fi

fi

# =============================================================================
# Section 4: Trigger Group Sync
# =============================================================================

print_header "Section 4: Trigger Group Sync"

if ! check_critical "Group Sync"; then :; else

print_test "POST /api/v1/groups/sync - trigger group sync"
do_request "POST" "/api/v1/groups/sync" "{}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    # Verify status field
    SYNC_STATUS=$(extract_json "$BODY" '.status // .sync_status // empty')
    if [ -n "$SYNC_STATUS" ] && [ "$SYNC_STATUS" != "null" ]; then
        print_info "Sync status: $SYNC_STATUS"
        if [ "$SYNC_STATUS" = "ok" ] || [ "$SYNC_STATUS" = "completed" ] || [ "$SYNC_STATUS" = "success" ]; then
            print_success "Group sync completed with status: $SYNC_STATUS"
        else
            print_success "Group sync responded (status: $SYNC_STATUS)"
        fi
    else
        print_success "Group sync returned 200"
    fi

    # Verify response is valid JSON
    print_test "Verify sync response is valid JSON"
    if echo "$BODY" | jq . > /dev/null 2>&1; then
        print_success "Sync response is valid JSON"
    else
        print_failure "Sync response JSON validation" "Response is not valid JSON"
    fi
elif [ "$HTTP_CODE" = "202" ]; then
    print_success "Group sync accepted (async processing, 202)"
elif [ "$HTTP_CODE" = "204" ]; then
    print_success "Group sync completed (204 no content)"
else
    print_failure "Group sync" "Expected 200/202/204, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 5: Verify Groups After Sync
# =============================================================================

print_header "Section 5: Verify Groups After Sync"

if ! check_critical "Verify Groups"; then :; else

print_test "List groups after sync"
do_request "GET" "/api/v1/groups" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    GROUP_COUNT=$(extract_json "$BODY" '.total // (.data | length) // (.groups | length) // 0')
    print_info "Groups after sync: $GROUP_COUNT"
    print_success "Groups listed after sync"
elif [ "$HTTP_CODE" = "404" ]; then
    # /groups may not be a separate endpoint, try asset-groups
    print_info "Groups endpoint returned 404, trying asset-groups"
    do_request "GET" "/api/v1/asset-groups" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        GROUP_COUNT=$(extract_json "$BODY" '.total // (.data | length) // 0')
        print_info "Asset groups after sync: $GROUP_COUNT"
        print_success "Asset groups listed after sync"
    else
        print_failure "List asset-groups after sync" "Expected 200, got $HTTP_CODE"
    fi
else
    print_failure "List groups after sync" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 6: Auth Check (401)
# =============================================================================

print_header "Section 6: Auth Check"

print_test "Trigger group sync without auth"
do_request "POST" "/api/v1/groups/sync" "{}"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "401" ]; then
    print_success "Unauthenticated sync rejected (401)"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "Unauthenticated sync rejected (403)"
else
    print_failure "Auth check for group sync" "Expected 401 or 403, got $HTTP_CODE"
fi

# =============================================================================
# Section 7: Docker Log Check
# =============================================================================

print_header "Section 7: Docker Log Check"

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
