#!/bin/bash
# =============================================================================
# End-to-End Platform Stats Test Script
# =============================================================================
# Tests the platform stats endpoint:
#   Register -> Login -> Create Team -> GET /platform/stats
#   -> Verify response fields -> Test without auth (401)
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_platform_stats.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_platform_stats.sh
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
TEST_EMAIL="e2e-pltstats-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E PlatStats User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E PlatStats Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-pltstats-${TIMESTAMP}"

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

print_header "E2E Platform Stats Test Suite"

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
# Section 3: Platform Stats - Authenticated
# =============================================================================

print_header "Section 3: Platform Stats (Authenticated)"

if ! check_critical "Platform Stats"; then :; else

print_test "GET /api/v1/platform/stats with auth"
do_request "GET" "/api/v1/platform/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Platform stats endpoint returned 200"

    # Verify expected JSON fields
    print_test "Verify 'enabled' field exists"
    ENABLED=$(extract_json "$BODY" '.enabled // .platform_enabled // empty')
    if [ -n "$ENABLED" ] && [ "$ENABLED" != "null" ]; then
        print_info "enabled: $ENABLED"
        print_success "Field 'enabled' present"
    else
        # Field might be nested or named differently
        HAS_ENABLED=$(echo "$BODY" | jq 'has("enabled") or has("platform_enabled")' 2>/dev/null)
        if [ "$HAS_ENABLED" = "true" ]; then
            print_success "Field 'enabled' present"
        else
            print_failure "Field 'enabled' missing" "Response does not contain 'enabled' or 'platform_enabled'"
        fi
    fi

    print_test "Verify 'max_tier' field exists"
    MAX_TIER=$(extract_json "$BODY" '.max_tier // empty')
    if [ -n "$MAX_TIER" ] && [ "$MAX_TIER" != "null" ]; then
        print_info "max_tier: $MAX_TIER"
        print_success "Field 'max_tier' present"
    else
        HAS_MAX_TIER=$(echo "$BODY" | jq 'has("max_tier")' 2>/dev/null)
        if [ "$HAS_MAX_TIER" = "true" ]; then
            print_success "Field 'max_tier' present"
        else
            print_failure "Field 'max_tier' missing" "Response does not contain 'max_tier'"
        fi
    fi

    print_test "Verify 'current_active' field exists"
    CURRENT_ACTIVE=$(extract_json "$BODY" '.current_active // empty')
    if [ -n "$CURRENT_ACTIVE" ] && [ "$CURRENT_ACTIVE" != "null" ]; then
        print_info "current_active: $CURRENT_ACTIVE"
        print_success "Field 'current_active' present"
    else
        HAS_CURRENT_ACTIVE=$(echo "$BODY" | jq 'has("current_active")' 2>/dev/null)
        if [ "$HAS_CURRENT_ACTIVE" = "true" ]; then
            print_success "Field 'current_active' present"
        else
            print_failure "Field 'current_active' missing" "Response does not contain 'current_active'"
        fi
    fi

    print_test "Verify 'current_queued' field exists"
    CURRENT_QUEUED=$(extract_json "$BODY" '.current_queued // empty')
    if [ -n "$CURRENT_QUEUED" ] && [ "$CURRENT_QUEUED" != "null" ]; then
        print_info "current_queued: $CURRENT_QUEUED"
        print_success "Field 'current_queued' present"
    else
        HAS_CURRENT_QUEUED=$(echo "$BODY" | jq 'has("current_queued")' 2>/dev/null)
        if [ "$HAS_CURRENT_QUEUED" = "true" ]; then
            print_success "Field 'current_queued' present"
        else
            print_failure "Field 'current_queued' missing" "Response does not contain 'current_queued'"
        fi
    fi

    print_test "Verify 'tier_stats' field exists"
    TIER_STATS=$(extract_json "$BODY" '.tier_stats // empty')
    if [ -n "$TIER_STATS" ] && [ "$TIER_STATS" != "null" ]; then
        print_info "tier_stats present"
        print_success "Field 'tier_stats' present"
    else
        HAS_TIER_STATS=$(echo "$BODY" | jq 'has("tier_stats")' 2>/dev/null)
        if [ "$HAS_TIER_STATS" = "true" ]; then
            print_success "Field 'tier_stats' present"
        else
            print_failure "Field 'tier_stats' missing" "Response does not contain 'tier_stats'"
        fi
    fi

    print_test "Verify response is valid JSON"
    if echo "$BODY" | jq . > /dev/null 2>&1; then
        print_success "Response is valid JSON"
    else
        print_failure "Response is not valid JSON"
    fi
else
    print_failure "Platform stats" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: Platform Stats - No Auth (401)
# =============================================================================

print_header "Section 4: Platform Stats Without Auth"

print_test "GET /api/v1/platform/stats without auth token"
do_request "GET" "/api/v1/platform/stats" ""
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "401" ]; then
    print_success "Unauthenticated request correctly rejected (401)"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "Unauthenticated request correctly rejected (403)"
else
    print_failure "Unauthenticated platform stats" "Expected 401 or 403, got $HTTP_CODE"
fi

# =============================================================================
# Section 5: Docker Log Check
# =============================================================================

print_header "Section 5: Docker Log Check"

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
