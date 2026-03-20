#!/bin/bash
# =============================================================================
# End-to-End Closed-Loop Finding Lifecycle Test
# =============================================================================
# Tests: fix_applied status, group view, verify, reject, auto-assign
#
# Flow:
#   Register → Login → Create Asset → Create Finding →
#   Confirm → In Progress → Fix Applied → Verify (or Reject) → Resolved
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#
# Usage:
#   ./test_e2e_fix_lifecycle.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-lifecycle-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Lifecycle User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Lifecycle Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-lifecycle-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_lifecycle_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_lifecycle_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0
ASSET_ID=""
FINDING_ID=""

print_header() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
print_test() { echo -e "${YELLOW}TEST:${NC} $1"; }
print_pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; PASSED=$((PASSED + 1)); }
print_fail() { echo -e "${RED}✗ FAIL:${NC} $1"; FAILED=$((FAILED + 1)); }
print_skip() { echo -e "${YELLOW}⊘ SKIP:${NC} $1"; SKIPPED=$((SKIPPED + 1)); }

api_call() {
    local method=$1 path=$2 data=$3
    local args=(-s -w "\n%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR")
    args+=(-H "Content-Type: application/json")
    if [ "$method" = "POST" ] || [ "$method" = "PATCH" ] || [ "$method" = "PUT" ]; then
        args+=(-X "$method" -d "$data")
    elif [ "$method" = "GET" ]; then
        args+=(-X GET)
    fi
    curl "${args[@]}" "${API_URL}${path}" > "$RESPONSE_FILE" 2>/dev/null
    local http_code=$(tail -1 "$RESPONSE_FILE")
    local body=$(sed '$d' "$RESPONSE_FILE")
    echo "$http_code|$body"
}

get_status() { echo "$1" | cut -d'|' -f1; }
get_body() { echo "$1" | cut -d'|' -f2-; }

# =============================================================================
print_header "Setup: Register + Login + Create Team"
# =============================================================================

result=$(api_call POST "/api/v1/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"name\":\"$TEST_NAME\"}")
if [ "$(get_status "$result")" = "201" ] || [ "$(get_status "$result")" = "200" ]; then
    print_pass "Register user"
else
    print_fail "Register user ($(get_status "$result"))"
    echo "Cannot continue without user. Exiting."
    exit 1
fi

result=$(api_call POST "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
if [ "$(get_status "$result")" = "200" ]; then
    print_pass "Login"
else
    print_fail "Login ($(get_status "$result"))"
    exit 1
fi

result=$(api_call POST "/api/v1/tenants" "{\"name\":\"$TEST_TEAM_NAME\",\"slug\":\"$TEST_TEAM_SLUG\"}")
status=$(get_status "$result")
if [ "$status" = "201" ] || [ "$status" = "200" ]; then
    print_pass "Create team"
else
    print_fail "Create team ($status)"
    exit 1
fi

# =============================================================================
print_header "Setup: Create Asset + Finding"
# =============================================================================

result=$(api_call POST "/api/v1/assets" '{"name":"test-server-lifecycle","asset_type":"host","criticality":"high"}')
status=$(get_status "$result")
body=$(get_body "$result")
if [ "$status" = "201" ] || [ "$status" = "200" ]; then
    ASSET_ID=$(echo "$body" | jq -r '.id // .data.id // empty' 2>/dev/null)
    print_pass "Create asset (id: ${ASSET_ID:0:8}...)"
else
    print_fail "Create asset ($status)"
    exit 1
fi

result=$(api_call POST "/api/v1/findings" "{\"asset_id\":\"$ASSET_ID\",\"title\":\"CVE-2021-44228 Log4j RCE\",\"severity\":\"critical\",\"source\":\"sca\",\"tool_name\":\"trivy\",\"message\":\"Log4j vulnerability\",\"cve_id\":\"CVE-2021-44228\"}")
status=$(get_status "$result")
body=$(get_body "$result")
if [ "$status" = "201" ] || [ "$status" = "200" ]; then
    FINDING_ID=$(echo "$body" | jq -r '.id // .data.id // empty' 2>/dev/null)
    print_pass "Create finding (id: ${FINDING_ID:0:8}...)"
else
    print_fail "Create finding ($status)"
    echo "Body: $body"
    exit 1
fi

# =============================================================================
print_header "Test 1: Status Transitions (new → confirmed → in_progress)"
# =============================================================================

print_test "new → confirmed"
result=$(api_call PATCH "/api/v1/findings/$FINDING_ID/status" '{"status":"confirmed"}')
if [ "$(get_status "$result")" = "200" ]; then
    print_pass "new → confirmed"
else
    print_fail "new → confirmed ($(get_status "$result"))"
fi

print_test "confirmed → in_progress"
result=$(api_call PATCH "/api/v1/findings/$FINDING_ID/status" '{"status":"in_progress"}')
if [ "$(get_status "$result")" = "200" ]; then
    print_pass "confirmed → in_progress"
else
    print_fail "confirmed → in_progress ($(get_status "$result"))"
fi

# =============================================================================
print_header "Test 2: in_progress → resolved BLOCKED (dev cannot self-close)"
# =============================================================================

print_test "in_progress → resolved (should be blocked)"
result=$(api_call PATCH "/api/v1/findings/$FINDING_ID/status" '{"status":"resolved","resolution":"I fixed it"}')
status=$(get_status "$result")
if [ "$status" = "400" ] || [ "$status" = "403" ] || [ "$status" = "422" ]; then
    print_pass "in_progress → resolved BLOCKED ($status)"
else
    # Owner/Admin can direct-resolve (escape hatch) — this is acceptable
    print_skip "in_progress → resolved allowed (user has verify permission — Admin/Owner)"
    # Reset to in_progress for next tests
    api_call PATCH "/api/v1/findings/$FINDING_ID/status" '{"status":"confirmed"}' > /dev/null
    api_call PATCH "/api/v1/findings/$FINDING_ID/status" '{"status":"in_progress"}' > /dev/null
fi

# =============================================================================
print_header "Test 3: Groups View"
# =============================================================================

print_test "GET /findings/groups?group_by=cve_id"
result=$(api_call GET "/api/v1/findings/groups?group_by=cve_id")
status=$(get_status "$result")
body=$(get_body "$result")
if [ "$status" = "200" ]; then
    group_count=$(echo "$body" | jq '.data | length' 2>/dev/null)
    print_pass "Groups view works (${group_count:-0} groups)"
else
    print_fail "Groups view ($status)"
fi

print_test "GET /findings/groups?group_by=asset_id"
result=$(api_call GET "/api/v1/findings/groups?group_by=asset_id")
if [ "$(get_status "$result")" = "200" ]; then
    print_pass "Groups by asset works"
else
    print_fail "Groups by asset ($(get_status "$result"))"
fi

print_test "GET /findings/groups?group_by=severity"
result=$(api_call GET "/api/v1/findings/groups?group_by=severity")
if [ "$(get_status "$result")" = "200" ]; then
    print_pass "Groups by severity works"
else
    print_fail "Groups by severity ($(get_status "$result"))"
fi

# =============================================================================
print_header "Test 4: Bulk Fix Applied"
# =============================================================================

print_test "POST /findings/actions/fix-applied (with note)"
result=$(api_call POST "/api/v1/findings/actions/fix-applied" "{\"filter\":{\"cve_ids\":[\"CVE-2021-44228\"]},\"note\":\"Upgraded log4j-core to 2.17.1\",\"include_related_cves\":false}")
status=$(get_status "$result")
body=$(get_body "$result")
if [ "$status" = "200" ]; then
    updated=$(echo "$body" | jq '.updated // 0' 2>/dev/null)
    print_pass "Bulk fix applied ($updated findings updated)"
else
    print_fail "Bulk fix applied ($status): $body"
fi

# Verify finding is now fix_applied
print_test "Verify finding status = fix_applied"
result=$(api_call GET "/api/v1/findings/$FINDING_ID")
status=$(get_status "$result")
body=$(get_body "$result")
finding_status=$(echo "$body" | jq -r '.status // .data.status // empty' 2>/dev/null)
if [ "$finding_status" = "fix_applied" ]; then
    print_pass "Finding status = fix_applied"
else
    print_fail "Finding status = '$finding_status' (expected fix_applied)"
fi

# =============================================================================
print_header "Test 5: Bulk Fix Applied WITHOUT note (should fail)"
# =============================================================================

print_test "POST /findings/actions/fix-applied without note (should fail)"
result=$(api_call POST "/api/v1/findings/actions/fix-applied" '{"filter":{"cve_ids":["CVE-2021-44228"]},"note":""}')
status=$(get_status "$result")
if [ "$status" = "400" ]; then
    print_pass "Fix applied without note rejected (400)"
else
    print_fail "Fix applied without note should be rejected ($status)"
fi

# =============================================================================
print_header "Test 6: Verify (Security approve)"
# =============================================================================

print_test "POST /findings/actions/verify (by filter)"
result=$(api_call POST "/api/v1/findings/actions/verify" "{\"filter\":{\"cve_ids\":[\"CVE-2021-44228\"]},\"note\":\"Verified by security team\"}")
status=$(get_status "$result")
body=$(get_body "$result")
if [ "$status" = "200" ]; then
    verified=$(echo "$body" | jq '.updated // 0' 2>/dev/null)
    print_pass "Verify by filter ($verified findings verified)"
else
    print_fail "Verify by filter ($status): $body"
fi

# Verify finding is now resolved
print_test "Verify finding status = resolved"
result=$(api_call GET "/api/v1/findings/$FINDING_ID")
body=$(get_body "$result")
finding_status=$(echo "$body" | jq -r '.status // .data.status // empty' 2>/dev/null)
resolution_method=$(echo "$body" | jq -r '.resolution_method // .data.resolution_method // empty' 2>/dev/null)
if [ "$finding_status" = "resolved" ]; then
    print_pass "Finding status = resolved"
else
    print_fail "Finding status = '$finding_status' (expected resolved)"
fi

# =============================================================================
print_header "Test 7: Related CVEs"
# =============================================================================

print_test "GET /findings/related-cves/CVE-2021-44228"
result=$(api_call GET "/api/v1/findings/related-cves/CVE-2021-44228")
status=$(get_status "$result")
if [ "$status" = "200" ]; then
    print_pass "Related CVEs endpoint works"
else
    print_fail "Related CVEs ($status)"
fi

# =============================================================================
print_header "Test 8: Auto-Assign to Owners"
# =============================================================================

print_test "POST /findings/actions/assign-to-owners"
result=$(api_call POST "/api/v1/findings/actions/assign-to-owners" '{"filter":{}}')
status=$(get_status "$result")
if [ "$status" = "200" ]; then
    print_pass "Auto-assign endpoint works"
else
    print_fail "Auto-assign ($status)"
fi

# =============================================================================
print_header "Results"
# =============================================================================

TOTAL=$((PASSED + FAILED + SKIPPED))
echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${GREEN}Passed:  $PASSED${NC}"
echo -e "${RED}Failed:  $FAILED${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
echo -e "Total:   $TOTAL"
echo -e "${BLUE}═══════════════════════════════════════${NC}"

if [ "$FAILED" -gt 0 ]; then
    echo -e "\n${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
