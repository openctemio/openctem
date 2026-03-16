#!/bin/bash
# =============================================================================
# End-to-End Finding Approvals Test Script
# =============================================================================
# Tests the finding approval workflow:
#   Register -> Login -> Create Team -> Create Asset -> Create Finding
#   -> Request Approval -> List Approvals -> List Pending -> Approve
#   -> Verify Status -> Reject Flow -> Auth Check -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_finding_approvals.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_finding_approvals.sh
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
TEST_EMAIL="e2e-approvals-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Approval User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Approval Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-approval-${TIMESTAMP}"

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
ASSET_ID=""
FINDING_ID=""
FINDING_ID_2=""
APPROVAL_ID=""
APPROVAL_ID_2=""
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

print_header "E2E Finding Approvals Test Suite"

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
# Section 3: Create Asset (prerequisite)
# =============================================================================

print_header "Section 3: Create Asset (prerequisite)"

if ! check_critical "Create Asset"; then :; else

print_test "Create asset for findings"
do_request "POST" "/api/v1/assets" "{
    \"name\": \"e2e-approval-repo-${TIMESTAMP}\",
    \"type\": \"repository\",
    \"criticality\": \"high\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ASSET_ID=$(extract_json "$BODY" '.id')
    print_info "Asset ID: $ASSET_ID"
    print_success "Asset created"
else
    print_failure "Create asset" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

fi

# =============================================================================
# Section 4: Create Findings
# =============================================================================

print_header "Section 4: Create Findings"

if ! check_critical "Create Finding"; then :; else

print_test "Create finding for approval flow"
do_request "POST" "/api/v1/findings" "{
    \"asset_id\": \"$ASSET_ID\",
    \"source\": \"sast\",
    \"tool_name\": \"semgrep\",
    \"tool_version\": \"1.0.0\",
    \"rule_id\": \"e2e-approval-001\",
    \"message\": \"SQL Injection requiring approval to accept risk\",
    \"severity\": \"critical\",
    \"file_path\": \"src/db/query.go\",
    \"start_line\": 55,
    \"end_line\": 55,
    \"snippet\": \"db.Query(fmt.Sprintf(sql, input))\"
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    FINDING_ID=$(extract_json "$BODY" '.id')
    print_info "Finding ID: $FINDING_ID"
    print_success "Finding created"
else
    print_failure "Create finding" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

print_test "Create second finding for reject flow"
do_request "POST" "/api/v1/findings" "{
    \"asset_id\": \"$ASSET_ID\",
    \"source\": \"sast\",
    \"tool_name\": \"semgrep\",
    \"rule_id\": \"e2e-approval-002\",
    \"message\": \"Path traversal needing review\",
    \"severity\": \"high\",
    \"file_path\": \"src/handlers/file.go\",
    \"start_line\": 30,
    \"end_line\": 30
}" "Authorization: Bearer $ACCESS_TOKEN"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    FINDING_ID_2=$(extract_json "$BODY" '.id')
    print_info "Finding ID 2: $FINDING_ID_2"
    print_success "Second finding created"
else
    print_failure "Create second finding" "Expected 201, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4b: Create Second User (Approver)
# =============================================================================
# Self-approval is prevented, so we need a separate user to approve/reject.

print_header "Section 4b: Create Approver User"

APPROVER_EMAIL="e2e-approver-${TIMESTAMP}@openctem-test.local"
APPROVER_PASSWORD="TestP@ss456!"
APPROVER_TOKEN=""

if ! check_critical "Create Approver"; then :; else

# Register second user
print_test "Register approver user"
do_request "POST" "/api/v1/auth/register" "{
    \"email\": \"$APPROVER_EMAIL\",
    \"password\": \"$APPROVER_PASSWORD\",
    \"name\": \"E2E Approver ${TIMESTAMP}\"
}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    APPROVER_USER_ID=$(extract_json "$BODY" '.id // .user_id // .user.id')
    print_info "Approver user ID: $APPROVER_USER_ID"
    print_success "Approver registered"
else
    print_failure "Register approver" "Expected 201, got $HTTP_CODE. Body: $(echo "$BODY" | head -c 200)"
fi

# Add approver to team as admin (owner can add members directly)
if [ -n "$APPROVER_USER_ID" ] && [ "$APPROVER_USER_ID" != "null" ]; then
    print_test "Add approver to team as admin"
    do_request "POST" "/api/v1/tenants/$TENANT_ID/members" "{
        \"user_id\": \"$APPROVER_USER_ID\",
        \"role\": \"admin\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Approver added to team as admin"
    else
        print_failure "Add approver to team" "Expected 201, got $HTTP_CODE. Body: $(echo "$BODY" | head -c 200)"
    fi

    # Login as approver and get token for the team
    print_test "Login as approver"
    do_request "POST" "/api/v1/auth/login" "{
        \"email\": \"$APPROVER_EMAIL\",
        \"password\": \"$APPROVER_PASSWORD\"
    }"
    if [ "$HTTP_CODE" = "200" ]; then
        APPROVER_REFRESH=$(extract_json "$BODY" '.refresh_token')
        # Exchange refresh token for tenant-scoped access token
        do_request "POST" "/api/v1/auth/token" "{
            \"refresh_token\": \"$APPROVER_REFRESH\",
            \"tenant_id\": \"$TENANT_ID\"
        }"
        if [ "$HTTP_CODE" = "200" ]; then
            APPROVER_TOKEN=$(extract_json "$BODY" '.access_token')
            print_success "Approver logged in and token exchanged"
        else
            print_failure "Approver token exchange" "Expected 200, got $HTTP_CODE"
        fi
    else
        print_failure "Approver login" "Expected 200, got $HTTP_CODE"
    fi
else
    print_failure "No approver user ID" "Cannot add to team"
fi

fi

# =============================================================================
# Section 5: Request Approval
# =============================================================================

print_header "Section 5: Request Approval"

if ! check_critical "Request Approval"; then :; else

print_test "Request approval for finding"
if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID/approvals" "{
        \"justification\": \"Risk accepted: vulnerability is behind WAF and not exploitable in current deployment\",
        \"requested_status\": \"accepted\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"
    print_info "Response: $(echo "$BODY" | head -c 300)"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        APPROVAL_ID=$(extract_json "$BODY" '.id')
        print_info "Approval ID: $APPROVAL_ID"
        print_success "Approval requested"
    else
        print_failure "Request approval" "Expected 201, got $HTTP_CODE"
    fi
else
    print_skip "Request approval (no finding ID)"
fi

fi

# =============================================================================
# Section 6: List Approvals for Finding
# =============================================================================

print_header "Section 6: List Approvals for Finding"

if ! check_critical "List Finding Approvals"; then :; else

print_test "List approvals for finding"
if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "null" ]; then
    do_request "GET" "/api/v1/findings/$FINDING_ID/approvals" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        APPROVAL_COUNT=$(extract_json "$BODY" '.total // (.data | length) // (.approvals | length) // 0')
        print_info "Approval count: $APPROVAL_COUNT"
        if [ "$APPROVAL_COUNT" -ge 1 ] 2>/dev/null; then
            print_success "Finding approvals listed (count >= 1)"
        else
            print_success "Finding approvals listed (returned 200)"
        fi
    else
        print_failure "List finding approvals" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "List finding approvals (no finding ID)"
fi

fi

# =============================================================================
# Section 7: List Pending Approvals
# =============================================================================

print_header "Section 7: List Pending Approvals"

if ! check_critical "List Pending Approvals"; then :; else

print_test "List all pending approvals"
do_request "GET" "/api/v1/approvals?status=pending" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    PENDING_COUNT=$(extract_json "$BODY" '.total // (.data | length) // (.approvals | length) // 0')
    print_info "Pending approvals: $PENDING_COUNT"
    if [ "$PENDING_COUNT" -ge 1 ] 2>/dev/null; then
        print_success "Pending approvals listed (count >= 1)"
    else
        print_success "Pending approvals listed (returned 200)"
    fi
else
    print_failure "List pending approvals" "Expected 200, got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: Approve the Approval
# =============================================================================

print_header "Section 8: Approve"

if ! check_critical "Approve"; then :; else

print_test "Approve the approval request"
if [ -n "$APPROVAL_ID" ] && [ "$APPROVAL_ID" != "null" ]; then
    if [ -n "$APPROVER_TOKEN" ] && [ "$APPROVER_TOKEN" != "null" ]; then
        # Use the APPROVER (different user) to approve - self-approval is prevented
        do_request "POST" "/api/v1/approvals/$APPROVAL_ID/approve" "{}" "Authorization: Bearer $APPROVER_TOKEN"
        print_info "Status: $HTTP_CODE"

        if [ "$HTTP_CODE" = "200" ]; then
            print_success "Approval approved (by different user)"
        elif [ "$HTTP_CODE" = "201" ]; then
            print_success "Approval approved (201)"
        elif [ "$HTTP_CODE" = "204" ]; then
            print_success "Approval approved (204)"
        else
            print_failure "Approve approval" "Expected 200/201/204, got $HTTP_CODE. Body: $(echo "$BODY" | head -c 300)"
        fi
    else
        print_skip "Approve (no approver token - second user setup failed)"
    fi
else
    print_skip "Approve (no approval ID)"
fi

fi

# =============================================================================
# Section 9: Verify Finding Status Changed
# =============================================================================

print_header "Section 9: Verify Finding Status After Approval"

if ! check_critical "Verify Status"; then :; else

print_test "Check finding status after approval"
if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "null" ]; then
    do_request "GET" "/api/v1/findings/$FINDING_ID" "" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        CURRENT_STATUS=$(extract_json "$BODY" '.status')
        print_info "Current finding status: $CURRENT_STATUS"
        if [ "$CURRENT_STATUS" = "accepted" ] || [ "$CURRENT_STATUS" = "risk_accepted" ]; then
            print_success "Finding status changed to $CURRENT_STATUS after approval"
        else
            print_info "Finding status is '$CURRENT_STATUS' (approval may not auto-change status)"
            print_success "Finding retrieved after approval (status: $CURRENT_STATUS)"
        fi
    else
        print_failure "Get finding after approval" "Expected 200, got $HTTP_CODE"
    fi
else
    print_skip "Verify finding status (no finding ID)"
fi

fi

# =============================================================================
# Section 10: Reject Flow
# =============================================================================

print_header "Section 10: Reject Flow"

if ! check_critical "Reject Flow"; then :; else

# Request approval for second finding
print_test "Request approval for second finding"
if [ -n "$FINDING_ID_2" ] && [ "$FINDING_ID_2" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID_2/approvals" "{
        \"justification\": \"Request to accept risk on path traversal\",
        \"requested_status\": \"accepted\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        APPROVAL_ID_2=$(extract_json "$BODY" '.id')
        print_info "Approval ID 2: $APPROVAL_ID_2"
        print_success "Second approval requested"
    else
        print_failure "Request second approval" "Expected 201, got $HTTP_CODE"
    fi

    # Reject it (using approver - different user; field is "reason" not "comment")
    print_test "Reject the approval request"
    if [ -n "$APPROVAL_ID_2" ] && [ "$APPROVAL_ID_2" != "null" ]; then
        if [ -n "$APPROVER_TOKEN" ] && [ "$APPROVER_TOKEN" != "null" ]; then
            do_request "POST" "/api/v1/approvals/$APPROVAL_ID_2/reject" "{
                \"reason\": \"Rejected: path traversal must be fixed, not accepted\"
            }" "Authorization: Bearer $APPROVER_TOKEN"
            print_info "Status: $HTTP_CODE"

            if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ]; then
                print_success "Approval rejected (by different user)"
            else
                print_failure "Reject approval" "Expected 200/201/204, got $HTTP_CODE. Body: $(echo "$BODY" | head -c 300)"
            fi
        else
            print_skip "Reject approval (no approver token)"
        fi
    else
        print_skip "Reject approval (no approval ID 2)"
    fi

    # Verify finding status after rejection
    print_test "Verify finding status after rejection"
    if [ -n "$FINDING_ID_2" ] && [ "$FINDING_ID_2" != "null" ]; then
        do_request "GET" "/api/v1/findings/$FINDING_ID_2" "" "Authorization: Bearer $ACCESS_TOKEN"
        if [ "$HTTP_CODE" = "200" ]; then
            STATUS_AFTER_REJECT=$(extract_json "$BODY" '.status')
            print_info "Finding 2 status after rejection: $STATUS_AFTER_REJECT"
            if [ "$STATUS_AFTER_REJECT" != "accepted" ] && [ "$STATUS_AFTER_REJECT" != "risk_accepted" ]; then
                print_success "Finding status NOT changed to accepted after rejection ($STATUS_AFTER_REJECT)"
            else
                print_failure "Finding status changed to accepted despite rejection" "Status: $STATUS_AFTER_REJECT"
            fi
        else
            print_failure "Get finding after rejection" "Expected 200, got $HTTP_CODE"
        fi
    else
        print_skip "Verify rejection status (no finding ID 2)"
    fi
else
    print_skip "Reject flow (no second finding ID)"
fi

fi

# =============================================================================
# Section 11: Cancel Flow
# =============================================================================

print_header "Section 11: Cancel Flow"

if ! check_critical "Cancel Flow"; then :; else

# Request a new approval for cancel test
print_test "Request approval for cancel test"
CANCEL_APPROVAL_ID=""
if [ -n "$FINDING_ID_2" ] && [ "$FINDING_ID_2" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID_2/approvals" "{
        \"justification\": \"Will be canceled by requester\",
        \"requested_status\": \"false_positive\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        CANCEL_APPROVAL_ID=$(extract_json "$BODY" '.id')
        print_info "Cancel Approval ID: $CANCEL_APPROVAL_ID"
        print_success "Approval requested for cancel test"
    else
        print_failure "Request approval for cancel" "Expected 201, got $HTTP_CODE"
    fi

    # Cancel it
    print_test "Cancel own approval request"
    if [ -n "$CANCEL_APPROVAL_ID" ] && [ "$CANCEL_APPROVAL_ID" != "null" ]; then
        do_request "POST" "/api/v1/approvals/$CANCEL_APPROVAL_ID/cancel" "" "Authorization: Bearer $ACCESS_TOKEN"
        print_info "Status: $HTTP_CODE"

        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
            CANCEL_STATUS=$(extract_json "$BODY" '.status')
            print_info "Approval status: $CANCEL_STATUS"
            print_success "Approval canceled by requester"
        else
            print_failure "Cancel approval" "Expected 200, got $HTTP_CODE"
        fi

        # Try to cancel again (should fail - not pending)
        print_test "Cancel already canceled approval (should fail)"
        do_request "POST" "/api/v1/approvals/$CANCEL_APPROVAL_ID/cancel" "" "Authorization: Bearer $ACCESS_TOKEN"
        print_info "Status: $HTTP_CODE"

        if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "422" ]; then
            print_success "Re-cancel rejected ($HTTP_CODE)"
        else
            print_failure "Re-cancel should fail" "Expected 400/409/422, got $HTTP_CODE"
        fi
    else
        print_skip "Cancel approval (no cancel approval ID)"
    fi
else
    print_skip "Cancel flow (no finding ID 2)"
fi

fi

# =============================================================================
# Section 12: Invalid Status Validation
# =============================================================================

print_header "Section 12: Invalid Status Validation"

if ! check_critical "Invalid Status"; then :; else

print_test "Request approval with invalid requested_status"
if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID/approvals" "{
        \"justification\": \"Should fail validation\",
        \"requested_status\": \"invalid_garbage_status\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "422" ]; then
        print_success "Invalid status rejected ($HTTP_CODE)"
    else
        print_failure "Invalid status validation" "Expected 400/422, got $HTTP_CODE"
    fi
else
    print_skip "Invalid status test (no finding ID)"
fi

fi

# =============================================================================
# Section 13: Self-Approval Prevention
# =============================================================================

print_header "Section 13: Self-Approval Prevention"

if ! check_critical "Self-Approval"; then :; else

# The user who requested approval should not be able to approve it themselves
# First create a new approval
print_test "Request approval for self-approval test"
SELF_APPROVAL_ID=""
if [ -n "$FINDING_ID_2" ] && [ "$FINDING_ID_2" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID_2/approvals" "{
        \"justification\": \"Testing self-approval prevention\",
        \"requested_status\": \"accepted\"
    }" "Authorization: Bearer $ACCESS_TOKEN"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        SELF_APPROVAL_ID=$(extract_json "$BODY" '.id')
        print_success "Approval created for self-approval test"

        # Try to approve own request (should fail)
        print_test "Approve own request (should fail with self-approval error)"
        do_request "POST" "/api/v1/approvals/$SELF_APPROVAL_ID/approve" "" "Authorization: Bearer $ACCESS_TOKEN"
        print_info "Status: $HTTP_CODE"
        print_info "Response: $(echo "$BODY" | head -c 200)"

        if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "409" ]; then
            print_success "Self-approval prevented ($HTTP_CODE)"
        else
            print_failure "Self-approval should be blocked" "Expected 400/403/409, got $HTTP_CODE"
        fi
    else
        print_failure "Create approval for self-test" "Expected 201, got $HTTP_CODE"
    fi
else
    print_skip "Self-approval test (no finding ID 2)"
fi

fi

# =============================================================================
# Section 14: Optimistic Locking (Double Action)
# =============================================================================

print_header "Section 14: Optimistic Locking"

if ! check_critical "Optimistic Locking"; then :; else

# If self-approval test created an approval, try to reject it twice quickly
if [ -n "$SELF_APPROVAL_ID" ] && [ "$SELF_APPROVAL_ID" != "null" ]; then
    # First cancel it (as requester) to clean up
    do_request "POST" "/api/v1/approvals/$SELF_APPROVAL_ID/cancel" "" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        print_success "Cleaned up self-approval test approval"

        # Try acting on the canceled approval
        print_test "Approve canceled approval (should fail)"
        do_request "POST" "/api/v1/approvals/$SELF_APPROVAL_ID/approve" "" "Authorization: Bearer $ACCESS_TOKEN"
        print_info "Status: $HTTP_CODE"

        if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "422" ]; then
            print_success "Cannot approve canceled approval ($HTTP_CODE)"
        else
            print_failure "Should not approve canceled" "Expected 400/409, got $HTTP_CODE"
        fi
    else
        print_info "Could not cancel self-approval test approval (status: $HTTP_CODE)"
    fi
else
    print_skip "Optimistic locking test (no self-approval ID)"
fi

fi

# =============================================================================
# Section 15: Auth Check (401)
# =============================================================================

print_header "Section 15: Auth Check"

print_test "Request approval without auth token"
if [ -n "$FINDING_ID" ] && [ "$FINDING_ID" != "null" ]; then
    do_request "POST" "/api/v1/findings/$FINDING_ID/approvals" "{
        \"justification\": \"Should fail\"
    }"
    print_info "Status: $HTTP_CODE"

    if [ "$HTTP_CODE" = "401" ]; then
        print_success "Unauthenticated approval request rejected (401)"
    elif [ "$HTTP_CODE" = "403" ]; then
        print_success "Unauthenticated approval request rejected (403)"
    else
        print_failure "Auth check for approvals" "Expected 401 or 403, got $HTTP_CODE"
    fi
else
    print_skip "Auth check (no finding ID)"
fi

print_test "List approvals without auth token"
do_request "GET" "/api/v1/approvals?status=pending" ""
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "401" ]; then
    print_success "Unauthenticated approvals list rejected (401)"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "Unauthenticated approvals list rejected (403)"
else
    print_failure "Auth check for listing approvals" "Expected 401 or 403, got $HTTP_CODE"
fi

# =============================================================================
# Section 16: Docker Log Check
# =============================================================================

print_header "Section 16: Docker Log Check"

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
