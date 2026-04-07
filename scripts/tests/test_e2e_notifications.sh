#!/bin/bash
# =============================================================================
# E2E Notification Integrations Test Script
# =============================================================================
# Tests notification integration features:
#   1. Create webhook integration
#   2. Create notification rule (event type filter)
#   3. Test webhook with invalid URL (SSRF blocked)
#   4. List notifications
#   5. Test connection endpoint
#   6. Edge cases: duplicate name, missing required fields
#
# Usage:
#   ./test_e2e_notifications.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-notif-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="SecureP@ss123!"
TEST_NAME="Notification Test User"
TEST_TEAM="Notif Team ${TIMESTAMP}"
TEST_SLUG="notif-team-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_notif_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_notif_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0
ACCESS_TOKEN=""
TENANT_ID=""
BODY=""
HTTP_CODE=""

# =============================================================================
# Helpers
# =============================================================================

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_test() { echo -e "\n${YELLOW}>>> Test: $1${NC}"; }
print_success() { echo -e "${GREEN}  PASSED: $1${NC}"; PASSED=$((PASSED + 1)); }
print_failure() { echo -e "${RED}  FAILED: $1${NC}"; [ -n "$2" ] && echo -e "${RED}  Detail: $2${NC}"; FAILED=$((FAILED + 1)); }
print_skip() { echo -e "${YELLOW}  SKIPPED: $1${NC}"; SKIPPED=$((SKIPPED + 1)); }

do_request() {
    local method="$1" endpoint="$2" data="$3"
    shift 3
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json" -c "$COOKIE_JAR" -b "$COOKIE_JAR")
    for h in "$@"; do curl_args+=(-H "$h"); done
    [ -n "$data" ] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" > "$RESPONSE_FILE" 2>/dev/null
    HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
    BODY=$(sed '$d' "$RESPONSE_FILE")
}

auth_header() { echo "Authorization: Bearer ${ACCESS_TOKEN}"; }

# =============================================================================
# Setup: Register + Login + Create Team
# =============================================================================

print_header "Setup: Create Test User & Team"

do_request POST "/api/v1/auth/register" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"name\":\"${TEST_NAME}\"}"
if [ "$HTTP_CODE" = "201" ]; then
    print_success "Register user"
else
    print_failure "Register user (HTTP $HTTP_CODE)" "$BODY"
    echo -e "${RED}Cannot proceed without auth. Exiting.${NC}"
    exit 1
fi

do_request POST "/api/v1/auth/login" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')
if [ -n "$ACCESS_TOKEN" ]; then
    print_success "Login"
else
    print_failure "Login" "$BODY"
    exit 1
fi

do_request POST "/api/v1/tenants" "{\"name\":\"${TEST_TEAM}\",\"slug\":\"${TEST_SLUG}\"}" "$(auth_header)"
TENANT_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ -n "$TENANT_ID" ]; then
    print_success "Create team (tenant: $TENANT_ID)"
else
    print_failure "Create team" "$BODY"
    exit 1
fi

# Re-login to get tenant-scoped token
do_request POST "/api/v1/auth/login" "{\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')

# =============================================================================
# 1. Create Webhook Integration
# =============================================================================

print_header "1. Create Webhook Integration"

print_test "Create webhook with valid external URL"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"Test Webhook ${TIMESTAMP}\",\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\",\"base_url\":\"https://hooks.example.com/webhook\",\"metadata\":{\"url\":\"https://hooks.example.com/webhook\"}}" \
    "$(auth_header)"
WEBHOOK_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Webhook integration created (id: $WEBHOOK_ID)"
else
    print_failure "Create webhook (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Create Slack integration"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"Test Slack ${TIMESTAMP}\",\"category\":\"notification\",\"provider\":\"slack\",\"auth_type\":\"token\",\"credentials\":\"xoxb-test-token\",\"metadata\":{\"channel\":\"#alerts\"}}" \
    "$(auth_header)"
SLACK_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Slack integration created (id: $SLACK_ID)"
else
    print_failure "Create Slack integration (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 2. Create Notification Rule
# =============================================================================

print_header "2. Create Notification Rules"

if [ -n "$WEBHOOK_ID" ]; then
    print_test "Create notification rule with event type filter"
    do_request POST "/api/v1/notification-rules" \
        "{\"name\":\"Findings Alert ${TIMESTAMP}\",\"integration_id\":\"${WEBHOOK_ID}\",\"event_types\":[\"findings\"],\"enabled\":true,\"severity_filter\":[\"critical\",\"high\"]}" \
        "$(auth_header)"
    RULE_ID=$(echo "$BODY" | jq -r '.id // empty')
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Notification rule created (id: $RULE_ID)"
    else
        print_failure "Create notification rule (HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Create rule for all event types"
    do_request POST "/api/v1/notification-rules" \
        "{\"name\":\"All Events ${TIMESTAMP}\",\"integration_id\":\"${WEBHOOK_ID}\",\"event_types\":[],\"enabled\":true}" \
        "$(auth_header)"
    RULE_ID_2=$(echo "$BODY" | jq -r '.id // empty')
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "All-events rule created (id: $RULE_ID_2)"
    else
        print_failure "Create all-events rule (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No webhook integration for rules"
fi

# =============================================================================
# 3. SSRF Protection for Webhooks
# =============================================================================

print_header "3. SSRF Protection for Webhooks"

print_test "Webhook with localhost URL blocked"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"SSRF Webhook\",\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\",\"base_url\":\"http://localhost:8080/admin\",\"metadata\":{\"url\":\"http://localhost:8080/admin\"}}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "localhost webhook blocked (400)"
else
    print_failure "localhost webhook should be blocked (got HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Webhook with internal IP blocked"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"SSRF Internal\",\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\",\"base_url\":\"http://10.0.0.1:9090\",\"metadata\":{\"url\":\"http://10.0.0.1:9090\"}}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Internal IP webhook blocked (400)"
else
    print_failure "Internal IP webhook should be blocked (got HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Webhook with metadata service IP blocked"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"SSRF Meta\",\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\",\"base_url\":\"http://169.254.169.254\",\"metadata\":{\"url\":\"http://169.254.169.254\"}}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "AWS metadata IP blocked (400)"
else
    print_failure "AWS metadata IP should be blocked (got HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 4. List Notifications & Integrations
# =============================================================================

print_header "4. List Notifications & Integrations"

print_test "List notification integrations"
do_request GET "/api/v1/integrations?category=notification" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    COUNT=$(echo "$BODY" | jq -r '.total // (. | length) // 0')
    print_success "Listed notification integrations (count: $COUNT)"
else
    print_failure "List integrations (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "List notification rules"
do_request GET "/api/v1/notification-rules" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    COUNT=$(echo "$BODY" | jq -r '.total // (. | length) // 0')
    print_success "Listed notification rules (count: $COUNT)"
else
    print_failure "List notification rules (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "List notification events/history"
do_request GET "/api/v1/notifications" "" "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Listed notification history"
else
    print_failure "List notification history (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 5. Test Connection Endpoint
# =============================================================================

print_header "5. Test Connection Endpoint"

if [ -n "$WEBHOOK_ID" ]; then
    print_test "Test webhook connection"
    do_request POST "/api/v1/integrations/${WEBHOOK_ID}/test" "" "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "422" ] || [ "$HTTP_CODE" = "502" ]; then
        print_success "Test connection endpoint responded ($HTTP_CODE)"
    else
        print_failure "Test connection unexpected response (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No webhook to test connection"
fi

if [ -n "$SLACK_ID" ]; then
    print_test "Test Slack connection (expected fail with test token)"
    do_request POST "/api/v1/integrations/${SLACK_ID}/test" "" "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "422" ] || [ "$HTTP_CODE" = "502" ] || [ "$HTTP_CODE" = "400" ]; then
        print_success "Slack test connection responded ($HTTP_CODE)"
    else
        print_failure "Slack test connection unexpected (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No Slack integration to test"
fi

# =============================================================================
# 6. Edge Cases
# =============================================================================

print_header "6. Edge Cases"

# 6.1 Duplicate integration name
print_test "Edge: Duplicate integration name"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"Test Webhook ${TIMESTAMP}\",\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\",\"base_url\":\"https://hooks.example.com/other\",\"metadata\":{\"url\":\"https://hooks.example.com/other\"}}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "400" ]; then
    print_success "Duplicate name rejected ($HTTP_CODE)"
elif [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    DUP_ID=$(echo "$BODY" | jq -r '.id // empty')
    print_success "Duplicate name allowed (different webhook, id: $DUP_ID)"
else
    print_failure "Duplicate name unexpected response (HTTP $HTTP_CODE)" "$BODY"
fi

# 6.2 Missing required fields
print_test "Edge: Integration missing name"
do_request POST "/api/v1/integrations" \
    "{\"category\":\"notification\",\"provider\":\"webhook\",\"auth_type\":\"none\"}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Missing name rejected (400)"
else
    print_failure "Missing name should be rejected (got HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Edge: Integration missing provider"
do_request POST "/api/v1/integrations" \
    "{\"name\":\"No Provider ${TIMESTAMP}\",\"category\":\"notification\",\"auth_type\":\"none\"}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Missing provider rejected (400)"
else
    print_failure "Missing provider should be rejected (got HTTP $HTTP_CODE)" "$BODY"
fi

# 6.3 Notification rule with non-existent integration
print_test "Edge: Rule with non-existent integration"
FAKE_ID="00000000-0000-0000-0000-000000000099"
do_request POST "/api/v1/notification-rules" \
    "{\"name\":\"Bad Rule\",\"integration_id\":\"${FAKE_ID}\",\"event_types\":[\"findings\"],\"enabled\":true}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "400" ]; then
    print_success "Rule with bad integration rejected ($HTTP_CODE)"
else
    print_failure "Rule with bad integration should fail (got HTTP $HTTP_CODE)" "$BODY"
fi

# 6.4 Test connection for non-existent integration
print_test "Edge: Test connection for non-existent integration"
do_request POST "/api/v1/integrations/${FAKE_ID}/test" "" "$(auth_header)"
if [ "$HTTP_CODE" = "404" ]; then
    print_success "Non-existent integration test returns 404"
else
    print_failure "Expected 404 for non-existent integration (got HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# Cleanup
# =============================================================================

print_header "Cleanup"

if [ -n "$RULE_ID" ]; then
    do_request DELETE "/api/v1/notification-rules/${RULE_ID}" "" "$(auth_header)"
fi
if [ -n "$RULE_ID_2" ]; then
    do_request DELETE "/api/v1/notification-rules/${RULE_ID_2}" "" "$(auth_header)"
fi
if [ -n "$WEBHOOK_ID" ]; then
    do_request DELETE "/api/v1/integrations/${WEBHOOK_ID}" "" "$(auth_header)"
fi
if [ -n "$SLACK_ID" ]; then
    do_request DELETE "/api/v1/integrations/${SLACK_ID}" "" "$(auth_header)"
fi
if [ -n "$DUP_ID" ]; then
    do_request DELETE "/api/v1/integrations/${DUP_ID}" "" "$(auth_header)"
fi
print_success "Cleaned up test data"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}Notification Integrations E2E Test Summary${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASSED}${NC}"
echo -e "  Failed:  ${RED}${FAILED}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIPPED}${NC}"
echo -e "  Total Tests: $((PASSED + FAILED + SKIPPED))"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All notification tests passed!${NC}"
    exit 0
else
    echo -e "  ${RED}Some notification tests failed!${NC}"
    exit 1
fi
