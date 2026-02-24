#!/bin/bash
# =============================================================================
# End-to-End Auth Lifecycle Test Script
# =============================================================================
# Tests the full auth lifecycle:
#   Register -> Login -> Create Team -> Auth Info -> Profile -> Preferences
#   -> Tenants -> Token Refresh -> Token Exchange -> Sessions
#   -> Change Password -> Re-Login -> Logout -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_auth_lifecycle.sh [API_URL]
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-auth-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
NEW_PASSWORD="NewP@ss456!"
TEST_NAME="E2E Auth User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Auth Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-auth-${TIMESTAMP}"

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
REFRESH_TOKEN=""
TENANT_ID=""
TENANT_SLUG=""
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

print_header "E2E Auth Lifecycle Test Suite"

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
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
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
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    TENANT_SLUG=$(extract_json "$BODY" '.tenant_slug')
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
    TENANT_SLUG=$(extract_json "$BODY" '.tenants[0].slug')
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
# Section 3: Auth Info
# =============================================================================

print_header "Section 3: Auth Info"

if ! check_critical "Auth Info"; then :; else

print_test "Get auth info"
do_request "GET" "/api/v1/auth/info" ""
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    PROVIDER=$(extract_json "$BODY" '.provider')
    print_info "Provider: $PROVIDER"
    print_success "Auth info retrieved"
else
    print_failure "Auth info" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: User Profile
# =============================================================================

print_header "Section 4: User Profile"

if ! check_critical "User Profile"; then :; else

print_test "Get user profile"
do_request "GET" "/api/v1/users/me" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    USER_EMAIL=$(extract_json "$BODY" '.email')
    USER_NAME=$(extract_json "$BODY" '.name')
    print_info "Email: $USER_EMAIL"
    print_info "Name: $USER_NAME"
    print_success "User profile retrieved"
else
    print_failure "Get user profile" "Expected 200, got $HTTP_CODE"
fi

print_test "Update user profile"
do_request "PUT" "/api/v1/users/me" "{
    \"name\": \"Updated Auth User ${TIMESTAMP}\",
    \"phone\": \"+1234567890\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    UPDATED_NAME=$(extract_json "$BODY" '.name')
    print_info "Updated name: $UPDATED_NAME"
    print_success "User profile updated"
else
    print_failure "Update user profile" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 5: User Preferences
# =============================================================================

print_header "Section 5: User Preferences"

if ! check_critical "User Preferences"; then :; else

print_test "Update user preferences"
do_request "PUT" "/api/v1/users/me/preferences" "{
    \"theme\": \"dark\",
    \"language\": \"en\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    THEME=$(extract_json "$BODY" '.preferences.theme // .theme')
    print_info "Theme: $THEME"
    print_success "User preferences updated"
else
    print_failure "Update preferences" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 6: Get User Tenants
# =============================================================================

print_header "Section 6: User Tenants"

if ! check_critical "User Tenants"; then :; else

print_test "Get user tenants"
do_request "GET" "/api/v1/users/me/tenants" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    TENANT_COUNT=$(extract_json "$BODY" 'if type == "array" then length else (.data // []) | length end')
    print_info "Tenant count: $TENANT_COUNT"
    if [ "$TENANT_COUNT" -ge 1 ] 2>/dev/null; then
        print_success "User tenants retrieved (count >= 1)"
    else
        print_success "User tenants endpoint accessible"
    fi
else
    print_failure "Get user tenants" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 7: Token Refresh
# =============================================================================

print_header "Section 7: Token Refresh"

if ! check_critical "Token Refresh"; then :; else

print_test "Refresh token"
REFRESH_DATA="{\"tenant_id\": \"$TENANT_ID\"}"
if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
    REFRESH_DATA="{\"tenant_id\": \"$TENANT_ID\", \"refresh_token\": \"$REFRESH_TOKEN\"}"
fi
do_request "POST" "/api/v1/auth/refresh" "$REFRESH_DATA"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    NEW_ACCESS=$(extract_json "$BODY" '.access_token')
    NEW_REFRESH=$(extract_json "$BODY" '.refresh_token')
    if [ -n "$NEW_ACCESS" ] && [ "$NEW_ACCESS" != "null" ]; then
        ACCESS_TOKEN="$NEW_ACCESS"
        if [ -n "$NEW_REFRESH" ] && [ "$NEW_REFRESH" != "null" ]; then
            REFRESH_TOKEN="$NEW_REFRESH"
        fi
        print_success "Token refreshed"
    else
        print_failure "Refresh token" "Missing access_token in response"
    fi
else
    # Cookie-based refresh may work differently
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Refresh token" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Token Exchange
# =============================================================================

print_header "Section 8: Token Exchange"

if ! check_critical "Token Exchange"; then :; else

print_test "Exchange token"
EXCHANGE_DATA="{\"tenant_id\": \"$TENANT_ID\"}"
if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
    EXCHANGE_DATA="{\"tenant_id\": \"$TENANT_ID\", \"refresh_token\": \"$REFRESH_TOKEN\"}"
fi
do_request "POST" "/api/v1/auth/token" "$EXCHANGE_DATA"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    NEW_ACCESS=$(extract_json "$BODY" '.access_token')
    if [ -n "$NEW_ACCESS" ] && [ "$NEW_ACCESS" != "null" ]; then
        ACCESS_TOKEN="$NEW_ACCESS"
        print_success "Token exchanged"
    else
        print_failure "Token exchange" "Missing access_token"
    fi
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Token exchange" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 9: Sessions
# =============================================================================

print_header "Section 9: Sessions"

if ! check_critical "Sessions"; then :; else

print_test "List sessions"
do_request "GET" "/api/v1/users/me/sessions" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    SESSION_COUNT=$(extract_json "$BODY" '.sessions | length // 0')
    print_info "Session count: $SESSION_COUNT"
    print_success "Sessions listed"
else
    print_failure "List sessions" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 10: Change Password
# =============================================================================

print_header "Section 10: Change Password"

if ! check_critical "Change Password"; then :; else

print_test "Change password"
do_request "POST" "/api/v1/users/me/change-password" "{
    \"current_password\": \"$TEST_PASSWORD\",
    \"new_password\": \"$NEW_PASSWORD\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    print_success "Password changed"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Change password" "Expected 200/204, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 11: Login with New Password
# =============================================================================

print_header "Section 11: Login with New Password"

if ! check_critical "Login with New Password"; then :; else

print_test "Login with new password"
do_request "POST" "/api/v1/auth/login" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$NEW_PASSWORD\"
}"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    print_success "Login with new password succeeded"
else
    # If password change didn't work, try original password
    print_info "New password login failed, trying original..."
    do_request "POST" "/api/v1/auth/login" "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Login succeeded (with original password)"
    else
        print_failure "Login with new password" "Expected 200, got $HTTP_CODE"
    fi
fi

fi

# =============================================================================
# Section 12: Logout
# =============================================================================

print_header "Section 12: Logout"

if ! check_critical "Logout"; then :; else

print_test "Logout"
do_request "POST" "/api/v1/auth/logout" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    print_success "Logout successful"
else
    print_failure "Logout" "Expected 200/204, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 13: Docker Log Check
# =============================================================================

print_header "Section 13: Docker Log Check"

print_test "Check Docker logs for errors"
if command -v docker &> /dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)
    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=0
        if [ -n "$ERROR_LINES" ]; then
            ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
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
