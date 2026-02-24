#!/bin/bash
# =============================================================================
# End-to-End Scope Management Test Script
# =============================================================================
# Tests scope lifecycle:
#   Register -> Login -> Create Team -> Scope Stats -> Target CRUD
#   -> Activate/Deactivate -> Scope Check -> Exclusions -> Schedules
#   -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#
# Usage:
#   ./test_e2e_scope.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-scope-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Scope User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Scope Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-scope-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
TARGET_ID=""
EXCLUSION_ID=""
SCHEDULE_ID=""
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
print_header "E2E Scope Management Test Suite"
echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

for cmd in jq curl; do command -v $cmd &>/dev/null || { echo -e "${RED}$cmd required.${NC}"; exit 1; }; done

# Health Check
print_header "Section 1: Health Check"
print_test "API Health Check"
do_request "GET" "/health" ""
[ "$HTTP_CODE" = "200" ] && print_success "API is healthy" || { print_failure "Health" "Got $HTTP_CODE"; exit 1; }

# Auth Flow
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
# Section 3: Scope Stats
# =============================================================================
print_header "Section 3: Scope Stats"

if ! check_critical "Scope Stats"; then :; else
print_test "Get scope stats"
do_request "GET" "/api/v1/scope/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Scope stats retrieved" || print_failure "Scope stats" "Got $HTTP_CODE"
fi

# =============================================================================
# Section 4: Scope Targets
# =============================================================================
print_header "Section 4: Scope Targets"

if ! check_critical "Create Target"; then :; else

print_test "Create scope target"
do_request "POST" "/api/v1/scope/targets" "{
    \"target_type\": \"domain\",
    \"pattern\": \"*.e2e-${TIMESTAMP}.example.com\",
    \"description\": \"E2E test scope target\",
    \"priority\": 50,
    \"tags\": [\"e2e-test\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    TARGET_ID=$(extract_json "$BODY" '.id')
    print_info "Target ID: $TARGET_ID"
    print_success "Scope target created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create target" "Got $HTTP_CODE"
fi

print_test "List scope targets"
do_request "GET" "/api/v1/scope/targets" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Targets listed" || print_failure "List targets" "Got $HTTP_CODE"

print_test "Get scope target"
if [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "null" ]; then
    do_request "GET" "/api/v1/scope/targets/$TARGET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get target" || print_failure "Get target" "Got $HTTP_CODE"
else
    print_skip "Get target (no ID)"
fi

print_test "Update scope target"
if [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "null" ]; then
    do_request "PUT" "/api/v1/scope/targets/$TARGET_ID" "{\"priority\": 80}" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Target updated" || print_failure "Update target" "Got $HTTP_CODE"
else
    print_skip "Update target (no ID)"
fi

print_test "Deactivate target"
if [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "null" ]; then
    do_request "POST" "/api/v1/scope/targets/$TARGET_ID/deactivate" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Target deactivated" || print_failure "Deactivate" "Got $HTTP_CODE"
else
    print_skip "Deactivate (no ID)"
fi

print_test "Activate target"
if [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "null" ]; then
    do_request "POST" "/api/v1/scope/targets/$TARGET_ID/activate" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Target activated" || print_failure "Activate" "Got $HTTP_CODE"
else
    print_skip "Activate (no ID)"
fi

fi

# =============================================================================
# Section 5: Scope Check
# =============================================================================
print_header "Section 5: Scope Check"

if ! check_critical "Scope Check"; then :; else
print_test "Check scope"
do_request "POST" "/api/v1/scope/check" "{
    \"asset_type\": \"domain\",
    \"value\": \"test.e2e-${TIMESTAMP}.example.com\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    IN_SCOPE=$(extract_json "$BODY" '.in_scope // .is_in_scope // "unknown"')
    print_info "In scope: $IN_SCOPE"
    print_success "Scope check performed"
else
    print_failure "Scope check" "Got $HTTP_CODE"
fi
fi

# =============================================================================
# Section 6: Scope Exclusions
# =============================================================================
print_header "Section 6: Scope Exclusions"

if ! check_critical "Exclusions"; then :; else

print_test "Create exclusion"
do_request "POST" "/api/v1/scope/exclusions" "{
    \"exclusion_type\": \"domain\",
    \"pattern\": \"internal.e2e-${TIMESTAMP}.example.com\",
    \"reason\": \"Internal system - excluded from E2E testing\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    EXCLUSION_ID=$(extract_json "$BODY" '.id')
    print_info "Exclusion ID: $EXCLUSION_ID"
    print_success "Exclusion created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create exclusion" "Got $HTTP_CODE"
fi

print_test "List exclusions"
do_request "GET" "/api/v1/scope/exclusions" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Exclusions listed" || print_failure "List exclusions" "Got $HTTP_CODE"

print_test "Approve exclusion"
if [ -n "$EXCLUSION_ID" ] && [ "$EXCLUSION_ID" != "null" ]; then
    do_request "POST" "/api/v1/scope/exclusions/$EXCLUSION_ID/approve" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Exclusion approved"
    else
        print_failure "Approve exclusion" "Got $HTTP_CODE"
    fi
else
    print_skip "Approve exclusion (no ID)"
fi

fi

# =============================================================================
# Section 7: Scan Schedules
# =============================================================================
print_header "Section 7: Scan Schedules"

if ! check_critical "Schedules"; then :; else

print_test "Create schedule"
do_request "POST" "/api/v1/scope/schedules" "{
    \"name\": \"E2E Schedule ${TIMESTAMP}\",
    \"description\": \"E2E test schedule\",
    \"scan_type\": \"full\",
    \"schedule_type\": \"manual\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SCHEDULE_ID=$(extract_json "$BODY" '.id')
    print_info "Schedule ID: $SCHEDULE_ID"
    print_success "Schedule created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create schedule" "Got $HTTP_CODE"
fi

print_test "List schedules"
do_request "GET" "/api/v1/scope/schedules" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Schedules listed" || print_failure "List schedules" "Got $HTTP_CODE"

print_test "Disable schedule"
if [ -n "$SCHEDULE_ID" ] && [ "$SCHEDULE_ID" != "null" ]; then
    do_request "POST" "/api/v1/scope/schedules/$SCHEDULE_ID/disable" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Schedule disabled" || print_failure "Disable schedule" "Got $HTTP_CODE"
else
    print_skip "Disable schedule (no ID)"
fi

fi

# =============================================================================
# Section 8: Delete Target
# =============================================================================
print_header "Section 8: Delete Target"

if ! check_critical "Delete Target"; then :; else
print_test "Delete target"
if [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/scope/targets/$TARGET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Target deleted" || print_failure "Delete target" "Got $HTTP_CODE"
else
    print_skip "Delete target (no ID)"
fi
fi

# =============================================================================
# Docker Log Check
# =============================================================================
print_header "Section 9: Docker Log Check"

print_test "Check Docker logs"
if command -v docker &>/dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)
    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=0; [ -n "$ERROR_LINES" ] && ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
        print_info "Panics: $PANIC_COUNT | Fatals: $FATAL_COUNT | Errors: $ERROR_COUNT"
        if [ "$PANIC_COUNT" -gt 0 ]; then print_failure "Docker: panics"
        elif [ "$FATAL_COUNT" -gt 0 ]; then print_failure "Docker: fatals"
        elif [ "$ERROR_COUNT" -gt 10 ]; then print_failure "Docker: >10 errors"
        else print_success "Docker logs clean"; fi
    else print_skip "Docker (no container)"; fi
else print_skip "Docker (not available)"; fi

# Summary
print_header "Test Summary"
TOTAL=$((PASSED + FAILED))
echo -e "\n  Total Tests: $TOTAL\n  ${GREEN}Passed: $PASSED${NC}\n  ${RED}Failed: $FAILED${NC}"
[ "$SKIPPED" -gt 0 ] && echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
echo ""
[ "$FAILED" -eq 0 ] && { echo -e "  ${GREEN}All tests passed!${NC}"; echo ""; exit 0; } || { echo -e "  ${RED}Some tests failed.${NC}"; echo ""; exit 1; }
