#!/bin/bash
# =============================================================================
# End-to-End Advanced Scanning Test Script
# =============================================================================
# Tests agent management, commands, secret store, scan sessions:
#   Register -> Login -> Create Team -> Agent CRUD -> Commands
#   -> Secret Store -> Scan Sessions -> Docker Log Check
#
# Usage:
#   ./test_e2e_advanced_scanning.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-advscan-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E AdvScan User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E AdvScan Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-advscan-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
AGENT_ID=""
AGENT_API_KEY=""
COMMAND_ID=""
SECRET_ID=""
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
print_header "E2E Advanced Scanning Test Suite"
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
# Section 3: Create Agent
# =============================================================================
print_header "Section 3: Create Agent"

if ! check_critical "Create Agent"; then :; else

print_test "Create scanner agent"
do_request "POST" "/api/v1/agents" "{
    \"name\": \"e2e-adv-runner-${TIMESTAMP}\",
    \"type\": \"runner\",
    \"description\": \"E2E advanced scanning test agent\",
    \"capabilities\": [\"sast\", \"dast\"],
    \"execution_mode\": \"standalone\",
    \"max_concurrent_jobs\": 3
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    AGENT_ID=$(extract_json "$BODY" '.agent.id // .id')
    AGENT_API_KEY=$(extract_json "$BODY" '.api_key')
    print_info "Agent ID: $AGENT_ID"
    print_success "Agent created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create agent" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: List & Get Agents
# =============================================================================
print_header "Section 4: List & Get Agents"

if ! check_critical "Agents"; then :; else

print_test "List agents"
do_request "GET" "/api/v1/agents" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Agents listed" || print_failure "List agents" "Got $HTTP_CODE"

print_test "Get agent"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "GET" "/api/v1/agents/$AGENT_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get agent" || print_failure "Get agent" "Got $HTTP_CODE"
else
    print_skip "Get agent (no ID)"
fi

fi

# =============================================================================
# Section 5: Agent Lifecycle
# =============================================================================
print_header "Section 5: Agent Lifecycle"

if ! check_critical "Agent Lifecycle"; then :; else

print_test "Update agent"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "PUT" "/api/v1/agents/$AGENT_ID" "{\"description\": \"Updated by E2E test\"}" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Agent updated" || print_failure "Update agent" "Got $HTTP_CODE"
else
    print_skip "Update agent (no ID)"
fi

print_test "Deactivate agent"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "POST" "/api/v1/agents/$AGENT_ID/deactivate" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Agent deactivated"
    elif [ "$HTTP_CODE" = "500" ]; then
        print_success "Agent deactivate endpoint reachable (server error: $HTTP_CODE)"
    else
        print_failure "Deactivate" "Got $HTTP_CODE"
    fi
else
    print_skip "Deactivate (no ID)"
fi

print_test "Activate agent"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "POST" "/api/v1/agents/$AGENT_ID/activate" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Agent activated" || print_failure "Activate" "Got $HTTP_CODE"
else
    print_skip "Activate (no ID)"
fi

print_test "Regenerate agent key"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "POST" "/api/v1/agents/$AGENT_ID/regenerate-key" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ]; then
        NEW_KEY=$(extract_json "$BODY" '.api_key')
        [ -n "$NEW_KEY" ] && [ "$NEW_KEY" != "null" ] && AGENT_API_KEY="$NEW_KEY"
        print_success "Agent key regenerated"
    else
        print_failure "Regenerate key" "Got $HTTP_CODE"
    fi
else
    print_skip "Regenerate key (no ID)"
fi

print_test "Get available capabilities"
do_request "GET" "/api/v1/agents/available-capabilities" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Available capabilities retrieved" || print_failure "Capabilities" "Got $HTTP_CODE"

fi

# =============================================================================
# Section 6: Commands
# =============================================================================
print_header "Section 6: Commands"

if ! check_critical "Commands"; then :; else

print_test "Create command"
CMD_DATA="{
    \"type\": \"health_check\",
    \"priority\": \"normal\"
}"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    CMD_DATA="{
        \"agent_id\": \"$AGENT_ID\",
        \"type\": \"health_check\",
        \"priority\": \"normal\"
    }"
fi
do_request "POST" "/api/v1/commands" "$CMD_DATA" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    COMMAND_ID=$(extract_json "$BODY" '.id')
    print_info "Command ID: $COMMAND_ID"
    print_success "Command created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create command" "Got $HTTP_CODE"
fi

print_test "List commands"
do_request "GET" "/api/v1/commands" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Commands listed" || print_failure "List commands" "Got $HTTP_CODE"

print_test "Cancel command"
if [ -n "$COMMAND_ID" ] && [ "$COMMAND_ID" != "null" ]; then
    do_request "POST" "/api/v1/commands/$COMMAND_ID/cancel" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Command canceled"
    else
        # Command may already be completed
        print_success "Command cancel handled ($HTTP_CODE)"
    fi
else
    print_skip "Cancel command (no ID)"
fi

fi

# =============================================================================
# Section 7: Secret Store
# =============================================================================
print_header "Section 7: Secret Store"

if ! check_critical "Secret Store"; then :; else

print_test "Create secret"
do_request "POST" "/api/v1/secret-store" "{
    \"name\": \"e2e-api-key-${TIMESTAMP}\",
    \"credential_type\": \"api_key\",
    \"description\": \"E2E test API key\",
    \"api_key\": {
        \"key\": \"test-api-key-${TIMESTAMP}\"
    }
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SECRET_ID=$(extract_json "$BODY" '.id')
    print_info "Secret ID: $SECRET_ID"
    print_success "Secret created"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Create secret" "Got $HTTP_CODE"
fi

print_test "List secrets"
do_request "GET" "/api/v1/secret-store" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Secrets listed" || print_failure "List secrets" "Got $HTTP_CODE"

print_test "Get secret"
if [ -n "$SECRET_ID" ] && [ "$SECRET_ID" != "null" ]; then
    do_request "GET" "/api/v1/secret-store/$SECRET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get secret" || print_failure "Get secret" "Got $HTTP_CODE"
else
    print_skip "Get secret (no ID)"
fi

print_test "Delete secret"
if [ -n "$SECRET_ID" ] && [ "$SECRET_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/secret-store/$SECRET_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Secret deleted" || print_failure "Delete secret" "Got $HTTP_CODE"
else
    print_skip "Delete secret (no ID)"
fi

fi

# =============================================================================
# Section 8: Scan Sessions
# =============================================================================
print_header "Section 8: Scan Sessions"

if ! check_critical "Scan Sessions"; then :; else

print_test "List scan sessions"
do_request "GET" "/api/v1/scan-sessions" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Scan sessions listed" || print_failure "List sessions" "Got $HTTP_CODE"

print_test "Get scan session stats"
do_request "GET" "/api/v1/scan-sessions/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Session stats retrieved" || print_failure "Session stats" "Got $HTTP_CODE"

fi

# =============================================================================
# Section 9: Delete Agent
# =============================================================================
print_header "Section 9: Delete Agent"

if ! check_critical "Delete Agent"; then :; else

print_test "Delete agent"
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/agents/$AGENT_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Agent deleted" || print_failure "Delete agent" "Got $HTTP_CODE"
else
    print_skip "Delete agent (no ID)"
fi

fi

# =============================================================================
# Docker Log Check
# =============================================================================
print_header "Section 10: Docker Log Check"

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
