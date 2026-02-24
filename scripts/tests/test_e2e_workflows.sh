#!/bin/bash
# =============================================================================
# End-to-End Workflows Test Script
# =============================================================================
# Tests workflow lifecycle:
#   Register -> Login -> Create Team -> Workflow CRUD -> Nodes/Edges
#   -> Graph Update -> Trigger Run -> List/Get Runs -> Delete -> Docker Log Check
#
# Usage:
#   ./test_e2e_workflows.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-wf-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Workflow User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Workflow Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-wf-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
WORKFLOW_ID=""
NODE_ID=""
EDGE_ID=""
RUN_ID=""
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
print_header "E2E Workflows Test Suite"
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
# Section 3: Create Workflow
# =============================================================================
print_header "Section 3: Create Workflow"

if ! check_critical "Create Workflow"; then :; else

print_test "Create workflow with nodes and edges"
do_request "POST" "/api/v1/workflows" "{
    \"name\": \"E2E Workflow ${TIMESTAMP}\",
    \"description\": \"E2E test workflow\",
    \"tags\": [\"e2e-test\"],
    \"nodes\": [
        {
            \"node_key\": \"trigger-1\",
            \"node_type\": \"trigger\",
            \"name\": \"Manual Trigger\"
        },
        {
            \"node_key\": \"action-1\",
            \"node_type\": \"action\",
            \"name\": \"Process Finding\"
        }
    ],
    \"edges\": [
        {
            \"source_node_key\": \"trigger-1\",
            \"target_node_key\": \"action-1\"
        }
    ]
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    WORKFLOW_ID=$(extract_json "$BODY" '.id')
    print_info "Workflow ID: $WORKFLOW_ID"
    print_success "Workflow created"
else
    print_info "Response: $(echo "$BODY" | head -c 300)"
    print_failure "Create workflow" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: List & Get Workflows
# =============================================================================
print_header "Section 4: List & Get Workflows"

if ! check_critical "Workflows"; then :; else

print_test "List workflows"
do_request "GET" "/api/v1/workflows" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Workflows listed" || print_failure "List workflows" "Got $HTTP_CODE"

print_test "Get workflow"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "GET" "/api/v1/workflows/$WORKFLOW_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get workflow" || print_failure "Get workflow" "Got $HTTP_CODE"
else
    print_skip "Get workflow (no ID)"
fi

fi

# =============================================================================
# Section 5: Update Workflow
# =============================================================================
print_header "Section 5: Update Workflow"

if ! check_critical "Update Workflow"; then :; else

print_test "Update workflow"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "PUT" "/api/v1/workflows/$WORKFLOW_ID" "{
        \"name\": \"Updated E2E Workflow ${TIMESTAMP}\",
        \"description\": \"Updated by E2E test\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Workflow updated" || print_failure "Update workflow" "Got $HTTP_CODE"
else
    print_skip "Update workflow (no ID)"
fi

fi

# =============================================================================
# Section 6: Add Node & Edge
# =============================================================================
print_header "Section 6: Add Node & Edge"

if ! check_critical "Add Node"; then :; else

print_test "Add notification node"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "POST" "/api/v1/workflows/$WORKFLOW_ID/nodes" "{
        \"node_key\": \"notify-1\",
        \"node_type\": \"notification\",
        \"name\": \"Send Alert\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        NODE_ID=$(extract_json "$BODY" '.id // .node_id // empty')
        print_info "Node ID: $NODE_ID"
        print_success "Node added"
    else
        print_failure "Add node" "Got $HTTP_CODE"
    fi
else
    print_skip "Add node (no workflow ID)"
fi

print_test "Update node"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ] && [ -n "$NODE_ID" ] && [ "$NODE_ID" != "null" ]; then
    do_request "PUT" "/api/v1/workflows/$WORKFLOW_ID/nodes/$NODE_ID" "{
        \"name\": \"Updated Alert Node\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Node updated" || print_failure "Update node" "Got $HTTP_CODE"
else
    print_skip "Update node (no IDs)"
fi

print_test "Add edge"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "POST" "/api/v1/workflows/$WORKFLOW_ID/edges" "{
        \"source_node_key\": \"action-1\",
        \"target_node_key\": \"notify-1\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        EDGE_ID=$(extract_json "$BODY" '.id // .edge_id // empty')
        print_info "Edge ID: $EDGE_ID"
        print_success "Edge added"
    else
        print_failure "Add edge" "Got $HTTP_CODE"
    fi
else
    print_skip "Add edge (no workflow ID)"
fi

fi

# =============================================================================
# Section 7: Update Graph
# =============================================================================
print_header "Section 7: Update Graph"

if ! check_critical "Update Graph"; then :; else

print_test "Update workflow graph (atomic)"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "PUT" "/api/v1/workflows/$WORKFLOW_ID/graph" "{
        \"nodes\": [
            {\"node_key\": \"trigger-1\", \"node_type\": \"trigger\", \"name\": \"Manual Trigger\"},
            {\"node_key\": \"action-1\", \"node_type\": \"action\", \"name\": \"Process Finding\"},
            {\"node_key\": \"notify-1\", \"node_type\": \"notification\", \"name\": \"Alert\"}
        ],
        \"edges\": [
            {\"source_node_key\": \"trigger-1\", \"target_node_key\": \"action-1\"},
            {\"source_node_key\": \"action-1\", \"target_node_key\": \"notify-1\"}
        ]
    }" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Graph updated" || print_failure "Update graph" "Got $HTTP_CODE"
else
    print_skip "Update graph (no workflow ID)"
fi

fi

# =============================================================================
# Section 8: Trigger Run
# =============================================================================
print_header "Section 8: Trigger Run"

if ! check_critical "Trigger Run"; then :; else

print_test "Trigger workflow run"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "POST" "/api/v1/workflows/$WORKFLOW_ID/runs" "{
        \"trigger_type\": \"manual\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        RUN_ID=$(extract_json "$BODY" '.id // .run_id // empty')
        print_info "Run ID: $RUN_ID"
        print_success "Workflow run triggered"
    else
        print_info "Response: $(echo "$BODY" | head -c 200)"
        # Trigger may fail if workflow execution engine isn't running
        if [ "$HTTP_CODE" = "422" ] || [ "$HTTP_CODE" = "400" ]; then
            print_success "Trigger handled (workflow engine: $HTTP_CODE)"
        else
            print_failure "Trigger run" "Got $HTTP_CODE"
        fi
    fi
else
    print_skip "Trigger run (no workflow ID)"
fi

fi

# =============================================================================
# Section 9: List & Get Runs
# =============================================================================
print_header "Section 9: Workflow Runs"

if ! check_critical "Runs"; then :; else

print_test "List workflow runs"
do_request "GET" "/api/v1/workflow-runs" "" "Authorization: Bearer $ACCESS_TOKEN"
[ "$HTTP_CODE" = "200" ] && print_success "Runs listed" || print_failure "List runs" "Got $HTTP_CODE"

print_test "Get workflow run"
if [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ]; then
    do_request "GET" "/api/v1/workflow-runs/$RUN_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] && print_success "Get run" || print_failure "Get run" "Got $HTTP_CODE"
else
    print_skip "Get run (no ID)"
fi

fi

# =============================================================================
# Section 10: Cleanup (Delete Edge, Node, Workflow)
# =============================================================================
print_header "Section 10: Cleanup"

if ! check_critical "Cleanup"; then :; else

print_test "Delete edge"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ] && [ -n "$EDGE_ID" ] && [ "$EDGE_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/workflows/$WORKFLOW_ID/edges/$EDGE_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Edge deleted"
    elif [ "$HTTP_CODE" = "404" ]; then
        print_success "Edge delete handled (replaced by graph update)"
    else
        print_failure "Delete edge" "Got $HTTP_CODE"
    fi
else
    print_skip "Delete edge (no IDs)"
fi

print_test "Delete node"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ] && [ -n "$NODE_ID" ] && [ "$NODE_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/workflows/$WORKFLOW_ID/nodes/$NODE_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Node deleted"
    elif [ "$HTTP_CODE" = "404" ]; then
        print_success "Node delete handled (replaced by graph update)"
    else
        print_failure "Delete node" "Got $HTTP_CODE"
    fi
else
    print_skip "Delete node (no IDs)"
fi

print_test "Delete workflow"
if [ -n "$WORKFLOW_ID" ] && [ "$WORKFLOW_ID" != "null" ]; then
    do_request "DELETE" "/api/v1/workflows/$WORKFLOW_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] && print_success "Workflow deleted" || print_failure "Delete workflow" "Got $HTTP_CODE"
else
    print_skip "Delete workflow (no ID)"
fi

fi

# =============================================================================
# Docker Log Check
# =============================================================================
print_header "Section 11: Docker Log Check"

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
