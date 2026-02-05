#!/bin/bash
# =============================================================================
# Test Agent Analytics API Endpoints
# =============================================================================
# This script tests all agent analytics endpoints available via Admin API.
#
# Usage:
#   ./test_agent_analytics.sh [ADMIN_KEY] [AGENT_ID] [API_URL]
#
# Environment variables (alternative to arguments):
#   ADMIN_API_KEY - Admin API key for authentication
#   AGENT_ID      - Agent ID to test with
#   API_URL       - Base API URL (default: http://localhost:8080)
#
# Examples:
#   ./test_agent_analytics.sh
#   ./test_agent_analytics.sh radm_xxx 24432599-c9fe-49c2-98fe-b13359bd5f9a
#   ADMIN_API_KEY=radm_xxx AGENT_ID=xxx ./test_agent_analytics.sh
# =============================================================================

# Don't use set -e because ((PASSED++)) returns 1 when PASSED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ADMIN_KEY="${1:-${ADMIN_API_KEY:-radm_3f5469793dcf2637f7eaa9fe17d97012}}"
AGENT_ID="${2:-${AGENT_ID:-24432599-c9fe-49c2-98fe-b13359bd5f9a}}"
API_URL="${3:-${API_URL:-http://localhost:8080}}"

# Counters
PASSED=0
FAILED=0

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
    echo -e "${GREEN}✓ PASSED: $1${NC}"
    PASSED=$((PASSED + 1))
}

print_failure() {
    echo -e "${RED}✗ FAILED: $1${NC}"
    echo -e "${RED}  Error: $2${NC}"
    FAILED=$((FAILED + 1))
}

# Make API request and validate response
# Usage: test_endpoint "Test Name" "METHOD" "endpoint" "expected_status" ["expected_field"]
test_endpoint() {
    local test_name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local expected_field="$5"

    print_test "$test_name"
    echo "  Endpoint: $method $endpoint"

    # Make request
    local response
    local http_code

    response=$(curl -s -w "\n%{http_code}" -X "$method" \
        "${API_URL}${endpoint}" \
        -H "X-Admin-API-Key: $ADMIN_KEY" \
        -H "Content-Type: application/json")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo "  Status: $http_code"
    echo "  Response: $body" | head -c 500
    [ ${#body} -gt 500 ] && echo "... (truncated)"
    echo ""

    # Validate status code
    if [ "$http_code" != "$expected_status" ]; then
        print_failure "$test_name" "Expected status $expected_status, got $http_code"
        return 1
    fi

    # Validate expected field if provided
    if [ -n "$expected_field" ]; then
        if echo "$body" | jq -e ".$expected_field" > /dev/null 2>&1; then
            print_success "$test_name"
        else
            print_failure "$test_name" "Expected field '$expected_field' not found in response"
            return 1
        fi
    else
        print_success "$test_name"
    fi
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

print_header "Agent Analytics API Test Suite"

echo -e "\nConfiguration:"
echo "  API URL:   $API_URL"
echo "  Admin Key: ${ADMIN_KEY:0:12}..."
echo "  Agent ID:  $AGENT_ID"

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    exit 1
fi

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required but not installed.${NC}"
    exit 1
fi

# Validate admin key
print_test "Validate Admin API Key"
auth_response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_URL}/api/v1/admin/auth/validate" \
    -H "X-Admin-API-Key: $ADMIN_KEY")
auth_code=$(echo "$auth_response" | tail -n1)

if [ "$auth_code" != "200" ]; then
    echo -e "${RED}Error: Invalid admin API key or API not reachable.${NC}"
    echo "Response code: $auth_code"
    echo "Response: $(echo "$auth_response" | sed '$d')"
    exit 1
fi
echo -e "${GREEN}✓ Admin key validated${NC}"

# =============================================================================
# Test Suite: Session Endpoints
# =============================================================================

print_header "Session Endpoints"

# Test 1: List Sessions
test_endpoint \
    "List Agent Sessions" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/sessions" \
    "200" \
    "total"

# Test 2: List Sessions with Pagination
test_endpoint \
    "List Sessions with Pagination" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/sessions?page=1&per_page=10" \
    "200" \
    "page"

# Test 3: Get Active Session (may return 404 if no active session)
print_test "Get Active Session"
active_response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_URL}/api/v1/admin/agents/${AGENT_ID}/sessions/active" \
    -H "X-Admin-API-Key: $ADMIN_KEY")
active_code=$(echo "$active_response" | tail -n1)
active_body=$(echo "$active_response" | sed '$d')

echo "  Endpoint: GET /api/v1/admin/agents/${AGENT_ID}/sessions/active"
echo "  Status: $active_code"
echo "  Response: $active_body"

if [ "$active_code" = "200" ] || [ "$active_code" = "404" ]; then
    print_success "Get Active Session (200 or 404 expected)"
else
    print_failure "Get Active Session" "Expected 200 or 404, got $active_code"
fi

# Test 4: Get Session Stats
test_endpoint \
    "Get Session Stats (default 30 days)" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/sessions/stats" \
    "200" \
    "total_sessions"

# Test 5: Get Session Stats with Custom Date Range
test_endpoint \
    "Get Session Stats with Date Range" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/sessions/stats?from=2025-01-01&to=2026-01-31" \
    "200" \
    "total_online_seconds"

# =============================================================================
# Test Suite: Daily Stats Endpoints
# =============================================================================

print_header "Daily Stats Endpoints"

# Test 6: List Daily Stats
test_endpoint \
    "List Daily Stats" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/stats" \
    "200" \
    "total"

# Test 7: List Daily Stats with Pagination
test_endpoint \
    "List Daily Stats with Pagination" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/stats?page=1&per_page=7" \
    "200" \
    "per_page"

# Test 8: Get Time Series Data
test_endpoint \
    "Get Agent Time Series (default 30 days)" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/stats/daily" \
    "200" \
    "agent_id"

# Test 9: Get Time Series with Custom Date Range
test_endpoint \
    "Get Time Series with Date Range" \
    "GET" \
    "/api/v1/admin/agents/${AGENT_ID}/stats/daily?from=2025-01-01&to=2026-01-31" \
    "200" \
    "from"

# =============================================================================
# Test Suite: Aggregated Stats Endpoints
# =============================================================================

print_header "Aggregated Stats Endpoints"

# Test 10: Get Platform Aggregated Stats
test_endpoint \
    "Get Aggregated Stats (default 30 days)" \
    "GET" \
    "/api/v1/admin/agents/stats/aggregated" \
    "200" \
    "stats"

# Test 11: Get Aggregated Stats with Date Range
test_endpoint \
    "Get Aggregated Stats with Date Range" \
    "GET" \
    "/api/v1/admin/agents/stats/aggregated?from=2025-01-01&to=2026-01-31" \
    "200" \
    "stats.unique_agents"

# =============================================================================
# Test Suite: Error Cases
# =============================================================================

print_header "Error Cases"

# Test 12: Invalid Agent ID
test_endpoint \
    "Invalid Agent ID (should return 400)" \
    "GET" \
    "/api/v1/admin/agents/invalid-uuid/sessions" \
    "400" \
    "error"

# Test 13: Non-existent Agent ID
test_endpoint \
    "Non-existent Agent ID (should return 200 with empty data)" \
    "GET" \
    "/api/v1/admin/agents/00000000-0000-0000-0000-000000000000/sessions" \
    "200" \
    "total"

# Test 14: Missing Auth Header
print_test "Missing Auth Header (should return 401)"
no_auth_response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_URL}/api/v1/admin/agents/${AGENT_ID}/sessions")
no_auth_code=$(echo "$no_auth_response" | tail -n1)
no_auth_body=$(echo "$no_auth_response" | sed '$d')

echo "  Endpoint: GET /api/v1/admin/agents/${AGENT_ID}/sessions (no auth)"
echo "  Status: $no_auth_code"
echo "  Response: $no_auth_body"

if [ "$no_auth_code" = "401" ]; then
    print_success "Missing Auth Header returns 401"
else
    print_failure "Missing Auth Header" "Expected 401, got $no_auth_code"
fi

# Test 15: Invalid Auth Header
print_test "Invalid Auth Header (should return 401)"
bad_auth_response=$(curl -s -w "\n%{http_code}" -X GET \
    "${API_URL}/api/v1/admin/agents/${AGENT_ID}/sessions" \
    -H "X-Admin-API-Key: invalid_key_12345")
bad_auth_code=$(echo "$bad_auth_response" | tail -n1)
bad_auth_body=$(echo "$bad_auth_response" | sed '$d')

echo "  Endpoint: GET /api/v1/admin/agents/${AGENT_ID}/sessions (invalid key)"
echo "  Status: $bad_auth_code"
echo "  Response: $bad_auth_body"

if [ "$bad_auth_code" = "401" ]; then
    print_success "Invalid Auth Header returns 401"
else
    print_failure "Invalid Auth Header" "Expected 401, got $bad_auth_code"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Test Summary"

TOTAL=$((PASSED + FAILED))
echo -e "\nTotal Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed.${NC}"
    exit 1
fi
