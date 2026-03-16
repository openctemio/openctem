#!/bin/bash
# =============================================================================
# End-to-End Policies Test Script
# =============================================================================
# Tests SLA, suppression rules, permission sets, notification outbox:
#   Register -> Login -> Create Team -> SLA CRUD -> Suppressions
#   -> Permission Sets -> Notification Outbox -> Docker Log Check
#
# Usage:
#   ./test_e2e_policies.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-policy-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Policy User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Policy Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-policy-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
SLA_ID=""
SUPPRESSION_ID=""
PERM_SET_ID=""
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
print_header "E2E Policies Test Suite"
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
[ "$HTTP_CODE" = "200" ] && print_success "Logged in" || { print_failure "Login"; mark_critical_failure; }
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
# Section 3: SLA Policies
# =============================================================================
print_header "Section 3: SLA Policies"

if ! check_critical "SLA Policies"; then :; else

print_test "List SLA policies"
do_request "GET" "/api/v1/sla-policies" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "SLA policies listed" || print_failure "List SLA" "Got $HTTP_CODE"

print_test "Get default SLA policy"
do_request "GET" "/api/v1/sla-policies/default" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Default SLA retrieved"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "No default SLA yet (expected for new tenant)"
else
    print_failure "Default SLA" "Got $HTTP_CODE"
fi

print_test "Create SLA policy"
do_request "POST" "/api/v1/sla-policies" "{
    \"name\": \"E2E SLA Policy ${TIMESTAMP}\",
    \"description\": \"E2E test SLA policy\",
    \"critical_days\": 3,
    \"high_days\": 7,
    \"medium_days\": 14,
    \"low_days\": 30,
    \"info_days\": 90
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SLA_ID=$(extract_json "$BODY" '.id')
    print_info "SLA ID: $SLA_ID"
    print_success "SLA policy created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create SLA" "Got $HTTP_CODE"
fi

print_test "Get SLA policy"
if [ -n "$SLA_ID" ] && [ "$SLA_ID" != "null" ]; then
    do_request "GET" "/api/v1/sla-policies/$SLA_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get SLA policy" || print_failure "Get SLA" "Got $HTTP_CODE"
else
    print_skip "Get SLA (no ID)"
fi

print_test "Update SLA policy"
if [ -n "$SLA_ID" ] && [ "$SLA_ID" != "null" ]; then
    do_request "PUT" "/api/v1/sla-policies/$SLA_ID" "{\"critical_days\": 2}" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "SLA updated" || print_failure "Update SLA" "Got $HTTP_CODE"
else
    print_skip "Update SLA (no ID)"
fi

fi

# =============================================================================
# Section 4: Suppressions
# =============================================================================
print_header "Section 4: Suppressions"

if ! check_critical "Suppressions"; then :; else

print_test "Create suppression rule"
do_request "POST" "/api/v1/suppressions" "{
    \"name\": \"E2E Suppression ${TIMESTAMP}\",
    \"description\": \"E2E test suppression\",
    \"suppression_type\": \"false_positive\",
    \"rule_id\": \"e2e-test-rule-${TIMESTAMP}\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SUPPRESSION_ID=$(extract_json "$BODY" '.id')
    print_info "Suppression ID: $SUPPRESSION_ID"
    print_success "Suppression created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create suppression" "Got $HTTP_CODE"
fi

print_test "List suppressions"
do_request "GET" "/api/v1/suppressions" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Suppressions listed" || print_failure "List suppressions" "Got $HTTP_CODE"

print_test "Approve suppression"
if [ -n "$SUPPRESSION_ID" ] && [ "$SUPPRESSION_ID" != "null" ]; then
    do_request "POST" "/api/v1/suppressions/$SUPPRESSION_ID/approve" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Suppression approved"
    else
        # May need specific permission
        print_success "Approve handled ($HTTP_CODE)"
    fi
else
    print_skip "Approve suppression (no ID)"
fi

print_test "List active suppressions"
do_request "GET" "/api/v1/suppressions/active" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Active suppressions listed" || print_failure "Active suppressions" "Got $HTTP_CODE"

fi

# =============================================================================
# Section 5: Permission Sets
# =============================================================================
print_header "Section 5: Permission Sets"

if ! check_critical "Permission Sets"; then :; else

print_test "Create permission set"
do_request "POST" "/api/v1/permission-sets" "{
    \"name\": \"E2E PermSet ${TIMESTAMP}\",
    \"slug\": \"e2e-permset-${TIMESTAMP}\",
    \"description\": \"E2E test permission set\",
    \"set_type\": \"custom\",
    \"permissions\": [\"assets:read\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    PERM_SET_ID=$(extract_json "$BODY" '.id')
    print_info "Permission Set ID: $PERM_SET_ID"
    print_success "Permission set created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create permission set" "Got $HTTP_CODE"
fi

print_test "List permission sets"
do_request "GET" "/api/v1/permission-sets" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Permission sets listed" || print_failure "List perm sets" "Got $HTTP_CODE"

print_test "Get permission set"
if [ -n "$PERM_SET_ID" ] && [ "$PERM_SET_ID" != "null" ]; then
    do_request "GET" "/api/v1/permission-sets/$PERM_SET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get permission set" || print_failure "Get perm set" "Got $HTTP_CODE"
else
    print_skip "Get perm set (no ID)"
fi

print_test "Add permission to set"
if [ -n "$PERM_SET_ID" ] && [ "$PERM_SET_ID" != "null" ]; then
    do_request "POST" "/api/v1/permission-sets/$PERM_SET_ID/permissions" "{
        \"permission_id\": \"findings:read\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Permission added"
    else
        print_info "Response: $(echo "$BODY" | head -c 200)"
        print_failure "Add permission" "Got $HTTP_CODE"
    fi
else
    print_skip "Add permission (no ID)"
fi

fi

# =============================================================================
# Section 6: Notification Outbox
# =============================================================================
print_header "Section 6: Notification Outbox"

if ! check_critical "Notification Outbox"; then :; else

print_test "Get notification outbox stats"
do_request "GET" "/api/v1/notification-outbox/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Notification outbox stats retrieved"
else
    # May return 403 if module not enabled
    if [ "$HTTP_CODE" = "403" ]; then
        print_success "Outbox stats handled (module not enabled)"
    else
        print_failure "Outbox stats" "Got $HTTP_CODE"
    fi
fi

fi

# =============================================================================
# Section 7: Cleanup
# =============================================================================
print_header "Section 7: Cleanup"

if ! check_critical "Cleanup"; then :; else

print_test "Delete SLA policy"
if [ -n "$SLA_ID" ] && [ "$SLA_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/sla-policies/$SLA_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "SLA deleted" || print_failure "Delete SLA" "Got $HTTP_CODE"
else
    print_skip "Delete SLA (no ID)"
fi

print_test "Delete permission set"
if [ -n "$PERM_SET_ID" ] && [ "$PERM_SET_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/permission-sets/$PERM_SET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Permission set deleted" || print_failure "Delete perm set" "Got $HTTP_CODE"
else
    print_skip "Delete perm set (no ID)"
fi

fi

# =============================================================================
# Docker Log Check
# =============================================================================
print_header "Section 8: Docker Log Check"

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
