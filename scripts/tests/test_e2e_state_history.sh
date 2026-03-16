#!/bin/bash
# =============================================================================
# End-to-End State History (Shadow IT Detection) Test Script
# =============================================================================
# Tests state history lifecycle:
#   Register -> Login -> Create Team -> Create Assets -> State History
#   -> Timeline -> Appearances -> Shadow IT -> Exposure Changes
#   -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#
# Usage:
#   ./test_e2e_state_history.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-sh-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E StateHistory User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E StateHistory Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-sh-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
ASSET_ID=""
CRITICAL_FAILURE=0

BODY=""
HTTP_CODE=""

print_header() { echo -e "\n${BLUE}==============================================================================${NC}\n${BLUE}$1${NC}\n${BLUE}==============================================================================${NC}"; }
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

check_critical() { [ "$CRITICAL_FAILURE" -eq 1 ] && { print_skip "$1 (skipped)"; return 1; }; return 0; }
mark_critical_failure() { CRITICAL_FAILURE=1; }

# =============================================================================
print_header "E2E State History (Shadow IT) Test Suite"
echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

for cmd in jq curl; do
    command -v $cmd &> /dev/null || { echo -e "${RED}Error: $cmd required.${NC}"; exit 1; }
done

# =============================================================================
# Section 1: Health Check
# =============================================================================
print_header "Section 1: Health Check"
print_test "API Health Check"
do_request "GET" "/health" ""
[ "$HTTP_CODE" = "200" ] && print_success "API is healthy" || { print_failure "Health check" "Got $HTTP_CODE"; exit 1; }

# =============================================================================
# Section 2: Auth Flow
# =============================================================================
print_header "Section 2: Authentication"

print_test "Register"
do_request "POST" "/api/v1/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"name\":\"$TEST_NAME\"}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then print_success "Registered"
elif [ "$HTTP_CODE" = "409" ]; then print_success "User exists"
elif [ "$HTTP_CODE" = "429" ]; then print_failure "Rate limited"; mark_critical_failure
else print_failure "Registration" "Got $HTTP_CODE"; mark_critical_failure; fi

if ! check_critical "Login"; then :; else
print_test "Login"
do_request "POST" "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
[ "$HTTP_CODE" = "200" ] && print_success "Logged in" || { print_failure "Login" "Got $HTTP_CODE"; mark_critical_failure; }
fi

if ! check_critical "Create Team"; then :; else
print_test "Create team"
do_request "POST" "/api/v1/auth/create-first-team" "{\"team_name\":\"$TEST_TEAM_NAME\",\"team_slug\":\"$TEST_TEAM_SLUG\"}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token'); TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] && print_success "Team created" || { print_failure "Missing token"; mark_critical_failure; }
elif [ "$HTTP_CODE" = "409" ]; then
    do_request "POST" "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
    RT=$(extract_json "$BODY" '.refresh_token'); TID=$(extract_json "$BODY" '.tenants[0].id')
    if [ -n "$TID" ] && [ "$TID" != "null" ]; then
        do_request "POST" "/api/v1/auth/token" "{\"refresh_token\":\"$RT\",\"tenant_id\":\"$TID\"}"
        [ "$HTTP_CODE" = "200" ] && { ACCESS_TOKEN=$(extract_json "$BODY" '.access_token'); TENANT_ID="$TID"; print_success "Token exchanged"; } || { print_failure "Exchange"; mark_critical_failure; }
    else print_failure "No tenants"; mark_critical_failure; fi
else print_failure "Create team" "Got $HTTP_CODE"; mark_critical_failure; fi
fi

# =============================================================================
# Section 3: Create Assets (to generate state history)
# =============================================================================
print_header "Section 3: Create Assets"

if ! check_critical "Create Assets"; then :; else
print_test "Create domain asset"
do_request "POST" "/api/v1/assets" "{
    \"name\": \"e2e-sh-${TIMESTAMP}.example.com\",
    \"type\": \"domain\",
    \"criticality\": \"high\"
}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_ID=$(extract_json "$BODY" '.id')
    print_info "Asset ID: $ASSET_ID"
    print_success "Asset created"
else
    print_failure "Create asset" "Got $HTTP_CODE"
fi
fi

# =============================================================================
# Section 4: State History Stats
# =============================================================================
print_header "Section 4: State History Stats"

if ! check_critical "State History Stats"; then :; else

print_test "Get state history stats"
do_request "GET" "/api/v1/state-history/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "State history stats retrieved"
else
    print_failure "State history stats" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 5: State History List
# =============================================================================
print_header "Section 5: State History List"

if ! check_critical "State History List"; then :; else

print_test "List all state changes"
do_request "GET" "/api/v1/state-history" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    SH_TOTAL=$(extract_json "$BODY" '.total // (.data | length) // 0')
    print_info "Total state changes: $SH_TOTAL"
    print_success "State history listed"
else
    print_failure "List state history" "Got $HTTP_CODE"
fi

print_test "List state history with filter"
do_request "GET" "/api/v1/state-history?change_type=appeared&limit=10" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Filtered state history listed"
else
    print_failure "Filtered state history" "Got $HTTP_CODE"
fi

print_test "Get state history for asset"
if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
    do_request "GET" "/api/v1/assets/$ASSET_ID/state-history" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        ASSET_SH=$(extract_json "$BODY" '.total // (.data | length) // 0')
        print_info "Asset state changes: $ASSET_SH"
        print_success "Asset state history retrieved"
    else
        print_failure "Asset state history" "Got $HTTP_CODE"
    fi
else
    print_skip "Asset state history (no ID)"
fi

fi

# =============================================================================
# Section 6: Timeline
# =============================================================================
print_header "Section 6: Timeline"

if ! check_critical "Timeline"; then :; else

print_test "Get daily activity timeline"
do_request "GET" "/api/v1/state-history/timeline" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Timeline retrieved"
else
    print_failure "Timeline" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 7: Appearances & Disappearances
# =============================================================================
print_header "Section 7: Appearances & Disappearances"

if ! check_critical "Appearances"; then :; else

print_test "Get recent appearances"
do_request "GET" "/api/v1/state-history/appearances" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Recent appearances retrieved"
else
    print_failure "Appearances" "Got $HTTP_CODE"
fi

print_test "Get recent disappearances"
do_request "GET" "/api/v1/state-history/disappearances" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Recent disappearances retrieved"
else
    print_failure "Disappearances" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Shadow IT & Exposure Changes
# =============================================================================
print_header "Section 8: Shadow IT & Exposure Changes"

if ! check_critical "Shadow IT"; then :; else

print_test "Get shadow IT candidates"
do_request "GET" "/api/v1/state-history/shadow-it" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Shadow IT candidates retrieved"
else
    print_failure "Shadow IT" "Got $HTTP_CODE"
fi

print_test "Get exposure changes"
do_request "GET" "/api/v1/state-history/exposure-changes" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Exposure changes retrieved"
else
    print_failure "Exposure changes" "Got $HTTP_CODE"
fi

print_test "Get newly exposed assets"
do_request "GET" "/api/v1/state-history/newly-exposed" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Newly exposed assets retrieved"
else
    print_failure "Newly exposed" "Got $HTTP_CODE"
fi

print_test "Get compliance changes"
do_request "GET" "/api/v1/state-history/compliance" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Compliance changes retrieved"
else
    print_failure "Compliance changes" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 9: Docker Log Check
# =============================================================================
print_header "Section 9: Docker Log Check"

print_test "Check Docker logs"
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
        if [ "$PANIC_COUNT" -gt 0 ]; then print_failure "Docker logs: panics"
        elif [ "$FATAL_COUNT" -gt 0 ]; then print_failure "Docker logs: fatals"
        elif [ "$ERROR_COUNT" -gt 10 ]; then print_failure "Docker: >10 errors"
        else print_success "Docker logs clean"; fi
    else print_skip "Docker log check (no container)"; fi
else print_skip "Docker log check (no docker)"; fi

# =============================================================================
print_header "Test Summary"
TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  Total Tests: $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
[ "$SKIPPED" -gt 0 ] && echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
echo ""
[ "$FAILED" -eq 0 ] && { echo -e "  ${GREEN}All tests passed!${NC}"; echo ""; exit 0; } || { echo -e "  ${RED}Some tests failed.${NC}"; echo ""; exit 1; }
