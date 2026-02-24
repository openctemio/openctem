#!/bin/bash
# =============================================================================
# End-to-End Integrations & System Features Test Script
# =============================================================================
# Tests integrations lifecycle:
#   Register -> Login -> Create Team -> Dashboard -> Integrations
#   -> Webhooks -> API Keys -> Audit Logs -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_integrations.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_integrations.sh
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
TEST_EMAIL="e2e-integ-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Integration User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Integration Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-integ-${TIMESTAMP}"

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
INTEGRATION_ID=""
WEBHOOK_ID=""
APIKEY_ID=""
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

print_header "E2E Integrations & System Features Test Suite"

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
# Section 3: Dashboard
# =============================================================================

print_header "Section 3: Dashboard"

if ! check_critical "Dashboard"; then :; else

print_test "Get dashboard stats"
do_request "GET" "/api/v1/dashboard/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Dashboard stats retrieved"
else
    print_failure "Dashboard stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: Integrations
# =============================================================================

print_header "Section 4: Integrations"

if ! check_critical "Integrations"; then :; else

print_test "Create integration"
do_request "POST" "/api/v1/integrations" "{
    \"name\": \"E2E Webhook Integration ${TIMESTAMP}\",
    \"description\": \"E2E test integration\",
    \"category\": \"notification\",
    \"provider\": \"webhook\",
    \"auth_type\": \"token\",
    \"base_url\": \"https://httpbin.org\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    INTEGRATION_ID=$(extract_json "$BODY" '.id')
    print_info "Integration ID: $INTEGRATION_ID"
    print_success "Integration created"
else
    print_failure "Create integration" "Expected 201, got $HTTP_CODE"
fi

print_test "List integrations"
do_request "GET" "/api/v1/integrations" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    INTEG_TOTAL=$(extract_json "$BODY" '.total // (.data | length) // 0')
    print_info "Total integrations: $INTEG_TOTAL"
    print_success "List integrations"
else
    print_failure "List integrations" "Expected 200, got $HTTP_CODE"
fi

print_test "Get integration by ID"
if [ -n "$INTEGRATION_ID" ] && [ "$INTEGRATION_ID" != "null" ]; then
    do_request "GET" "/api/v1/integrations/$INTEGRATION_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get integration by ID"
    else
        print_failure "Get integration" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get integration (no ID)"
fi

print_test "Disable integration"
if [ -n "$INTEGRATION_ID" ] && [ "$INTEGRATION_ID" != "null" ]; then
    do_request "POST" "/api/v1/integrations/$INTEGRATION_ID/disable" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Integration disabled"
    else
        print_failure "Disable integration" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Disable integration (no ID)"
fi

print_test "Enable integration"
if [ -n "$INTEGRATION_ID" ] && [ "$INTEGRATION_ID" != "null" ]; then
    do_request "POST" "/api/v1/integrations/$INTEGRATION_ID/enable" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Integration enabled"
    elif [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
        # Enable calls TestIntegration which tests the actual connection.
        # Without real credentials, the test fails - this is expected behavior.
        print_success "Integration enable attempted (connection test failed as expected without real credentials)"
    else
        print_failure "Enable integration" "Expected 200/400, got $HTTP_CODE"
    fi
else
    print_skip "Enable integration (no ID)"
fi

fi

# =============================================================================
# Section 5: Webhooks
# =============================================================================

print_header "Section 5: Webhooks"

if ! check_critical "Webhooks"; then :; else

print_test "Create webhook"
do_request "POST" "/api/v1/webhooks" "{
    \"name\": \"E2E Test Webhook ${TIMESTAMP}\",
    \"description\": \"E2E test webhook\",
    \"url\": \"https://httpbin.org/post\",
    \"event_types\": [\"finding.created\", \"finding.resolved\"],
    \"severity_threshold\": \"high\",
    \"max_retries\": 3
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    WEBHOOK_ID=$(extract_json "$BODY" '.id')
    print_info "Webhook ID: $WEBHOOK_ID"
    print_success "Webhook created"
else
    print_failure "Create webhook" "Expected 201, got $HTTP_CODE"
fi

print_test "List webhooks"
do_request "GET" "/api/v1/webhooks" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "List webhooks"
else
    print_failure "List webhooks" "Expected 200, got $HTTP_CODE"
fi

print_test "Get webhook by ID"
if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
    do_request "GET" "/api/v1/webhooks/$WEBHOOK_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Get webhook by ID"
    else
        print_failure "Get webhook" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Get webhook (no ID)"
fi

print_test "Disable webhook"
if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
    do_request "POST" "/api/v1/webhooks/$WEBHOOK_ID/disable" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Webhook disabled"
    else
        print_failure "Disable webhook" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Disable webhook (no ID)"
fi

fi

# =============================================================================
# Section 6: API Keys
# =============================================================================

print_header "Section 6: API Keys"

if ! check_critical "API Keys"; then :; else

print_test "Create API key"
do_request "POST" "/api/v1/api-keys" "{
    \"name\": \"E2E Test API Key ${TIMESTAMP}\",
    \"description\": \"E2E test API key\",
    \"scopes\": [\"read\"],
    \"expires_in_days\": 30
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    APIKEY_ID=$(extract_json "$BODY" '.id')
    APIKEY_VALUE=$(extract_json "$BODY" '.key // .api_key // empty')
    print_info "API Key ID: $APIKEY_ID"
    if [ -n "$APIKEY_VALUE" ] && [ "$APIKEY_VALUE" != "null" ]; then
        print_info "API Key: ${APIKEY_VALUE:0:12}..."
    fi
    print_success "API key created"
else
    print_failure "Create API key" "Expected 201, got $HTTP_CODE"
fi

print_test "List API keys"
do_request "GET" "/api/v1/api-keys" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "List API keys"
else
    print_failure "List API keys" "Expected 200, got $HTTP_CODE"
fi

print_test "Revoke API key"
if [ -n "$APIKEY_ID" ] && [ "$APIKEY_ID" != "null" ]; then
    do_request "POST" "/api/v1/api-keys/$APIKEY_ID/revoke" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "API key revoked"
    else
        print_failure "Revoke API key" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Revoke API key (no ID)"
fi

fi

# =============================================================================
# Section 7: Audit Logs
# =============================================================================

print_header "Section 7: Audit Logs"

if ! check_critical "Audit Logs"; then :; else

print_test "List audit logs"
do_request "GET" "/api/v1/audit-logs" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "200" ]; then
    AUDIT_TOTAL=$(extract_json "$BODY" '.total // (.data | length) // 0')
    print_info "Total audit entries: $AUDIT_TOTAL"
    print_success "List audit logs"
else
    print_failure "List audit logs" "Expected 200, got $HTTP_CODE"
fi

print_test "Get audit log stats"
do_request "GET" "/api/v1/audit-logs/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Audit log stats"
else
    print_failure "Audit log stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Docker Log Check
# =============================================================================

print_header "Section 8: Docker Log Check"

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
