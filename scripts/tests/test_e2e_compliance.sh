#!/bin/bash
# =============================================================================
# E2E Compliance Framework Test Script
# =============================================================================
# Tests compliance framework features:
#   1. Create compliance assessment
#   2. Map assets to compliance frameworks
#   3. Create/update control status
#   4. List controls by framework
#   5. Assessment scoring
#   6. Edge cases: invalid framework name, duplicate mapping
#
# Usage:
#   ./test_e2e_compliance.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-comp-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="SecureP@ss123!"
TEST_NAME="Compliance Test User"
TEST_TEAM="Compliance Team ${TIMESTAMP}"
TEST_SLUG="comp-team-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_comp_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_comp_response.XXXXXX)
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
# 1. Create Compliance Framework
# =============================================================================

print_header "1. Create Compliance Framework"

print_test "Create a compliance framework (SOC2)"
do_request POST "/api/v1/compliance/frameworks" \
    "{\"name\":\"SOC2 ${TIMESTAMP}\",\"description\":\"SOC 2 Type II compliance framework\",\"version\":\"2024\"}" \
    "$(auth_header)"
FRAMEWORK_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Framework created (id: $FRAMEWORK_ID)"
else
    print_failure "Create framework (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Create a second framework (ISO27001)"
do_request POST "/api/v1/compliance/frameworks" \
    "{\"name\":\"ISO27001 ${TIMESTAMP}\",\"description\":\"ISO 27001 information security\",\"version\":\"2022\"}" \
    "$(auth_header)"
FRAMEWORK_ID_2=$(echo "$BODY" | jq -r '.id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Second framework created (id: $FRAMEWORK_ID_2)"
else
    print_failure "Create second framework (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 2. Create Compliance Controls
# =============================================================================

print_header "2. Create Compliance Controls"

if [ -n "$FRAMEWORK_ID" ]; then
    print_test "Create control under SOC2 framework"
    do_request POST "/api/v1/compliance/frameworks/${FRAMEWORK_ID}/controls" \
        "{\"name\":\"Access Control\",\"code\":\"CC6.1\",\"description\":\"Logical and physical access controls\"}" \
        "$(auth_header)"
    CONTROL_ID=$(echo "$BODY" | jq -r '.id // empty')
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Control created (id: $CONTROL_ID)"
    else
        print_failure "Create control (HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Create second control"
    do_request POST "/api/v1/compliance/frameworks/${FRAMEWORK_ID}/controls" \
        "{\"name\":\"Change Management\",\"code\":\"CC8.1\",\"description\":\"Changes to infrastructure and software\"}" \
        "$(auth_header)"
    CONTROL_ID_2=$(echo "$BODY" | jq -r '.id // empty')
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Second control created (id: $CONTROL_ID_2)"
    else
        print_failure "Create second control (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No framework to add controls to"
fi

# =============================================================================
# 3. List Controls by Framework
# =============================================================================

print_header "3. List Controls by Framework"

if [ -n "$FRAMEWORK_ID" ]; then
    print_test "List controls for SOC2 framework"
    do_request GET "/api/v1/compliance/frameworks/${FRAMEWORK_ID}/controls" "" "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ]; then
        COUNT=$(echo "$BODY" | jq -r '.total // (. | length) // 0')
        print_success "Listed controls (count: $COUNT)"
    else
        print_failure "List controls (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No framework to list controls for"
fi

# =============================================================================
# 4. Create Assessment and Map Assets
# =============================================================================

print_header "4. Create Assessment & Map Assets"

# Create a test asset first
do_request POST "/api/v1/assets" \
    "{\"name\":\"Compliance Test Asset ${TIMESTAMP}\",\"type\":\"domain\",\"criticality\":\"high\"}" \
    "$(auth_header)"
ASSET_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ -n "$ASSET_ID" ]; then
    print_success "Created test asset: $ASSET_ID"
else
    print_failure "Failed to create test asset" "$BODY"
fi

if [ -n "$FRAMEWORK_ID" ]; then
    print_test "Create compliance assessment"
    do_request POST "/api/v1/compliance/assessments" \
        "{\"framework_id\":\"${FRAMEWORK_ID}\",\"name\":\"Q1 Assessment ${TIMESTAMP}\",\"status\":\"in_progress\"}" \
        "$(auth_header)"
    ASSESSMENT_ID=$(echo "$BODY" | jq -r '.id // empty')
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Assessment created (id: $ASSESSMENT_ID)"
    else
        print_failure "Create assessment (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No framework for assessment"
fi

# Map asset to framework
if [ -n "$FRAMEWORK_ID" ] && [ -n "$ASSET_ID" ]; then
    print_test "Map asset to compliance framework"
    do_request POST "/api/v1/compliance/frameworks/${FRAMEWORK_ID}/assets" \
        "{\"asset_id\":\"${ASSET_ID}\"}" \
        "$(auth_header)"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Asset mapped to framework"
    else
        print_failure "Map asset to framework (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No framework or asset to map"
fi

# =============================================================================
# 5. Update Control Status
# =============================================================================

print_header "5. Update Control Status"

if [ -n "$CONTROL_ID" ] && [ -n "$ASSESSMENT_ID" ]; then
    print_test "Update control status to compliant"
    do_request PUT "/api/v1/compliance/assessments/${ASSESSMENT_ID}/controls/${CONTROL_ID}" \
        "{\"status\":\"compliant\",\"evidence\":\"Access controls reviewed and verified\",\"notes\":\"All checks passed\"}" \
        "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        print_success "Control status updated to compliant"
    else
        print_failure "Update control status (HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Update second control to non-compliant"
    do_request PUT "/api/v1/compliance/assessments/${ASSESSMENT_ID}/controls/${CONTROL_ID_2}" \
        "{\"status\":\"non_compliant\",\"evidence\":\"Missing change approval process\",\"notes\":\"Needs remediation\"}" \
        "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        print_success "Control status updated to non_compliant"
    else
        print_failure "Update second control status (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No control or assessment to update"
fi

# =============================================================================
# 6. Assessment Scoring
# =============================================================================

print_header "6. Assessment Scoring"

if [ -n "$ASSESSMENT_ID" ]; then
    print_test "Get assessment score/summary"
    do_request GET "/api/v1/compliance/assessments/${ASSESSMENT_ID}" "" "$(auth_header)"
    if [ "$HTTP_CODE" = "200" ]; then
        SCORE=$(echo "$BODY" | jq -r '.score // .compliance_score // .summary.score // "N/A"')
        print_success "Assessment retrieved (score: $SCORE)"
    else
        print_failure "Get assessment (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No assessment to score"
fi

# =============================================================================
# 7. Edge Cases
# =============================================================================

print_header "7. Edge Cases"

# 7.1 Invalid framework name (empty)
print_test "Edge: Empty framework name rejected"
do_request POST "/api/v1/compliance/frameworks" \
    "{\"name\":\"\",\"description\":\"No name\",\"version\":\"1.0\"}" \
    "$(auth_header)"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Empty framework name rejected (400)"
else
    print_failure "Empty name should be rejected (got HTTP $HTTP_CODE)" "$BODY"
fi

# 7.2 Duplicate asset mapping
if [ -n "$FRAMEWORK_ID" ] && [ -n "$ASSET_ID" ]; then
    print_test "Edge: Duplicate asset-to-framework mapping"
    do_request POST "/api/v1/compliance/frameworks/${FRAMEWORK_ID}/assets" \
        "{\"asset_id\":\"${ASSET_ID}\"}" \
        "$(auth_header)"
    if [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "Duplicate mapping handled ($HTTP_CODE)"
    else
        print_failure "Duplicate mapping unexpected response (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No framework or asset for duplicate test"
fi

# 7.3 Non-existent framework
print_test "Edge: Get non-existent framework returns 404"
FAKE_ID="00000000-0000-0000-0000-000000000099"
do_request GET "/api/v1/compliance/frameworks/${FAKE_ID}" "" "$(auth_header)"
if [ "$HTTP_CODE" = "404" ]; then
    print_success "Non-existent framework returns 404"
else
    print_failure "Expected 404 for non-existent framework (got HTTP $HTTP_CODE)" "$BODY"
fi

# 7.4 Invalid control status
if [ -n "$CONTROL_ID" ] && [ -n "$ASSESSMENT_ID" ]; then
    print_test "Edge: Invalid control status rejected"
    do_request PUT "/api/v1/compliance/assessments/${ASSESSMENT_ID}/controls/${CONTROL_ID}" \
        "{\"status\":\"super_compliant\"}" \
        "$(auth_header)"
    if [ "$HTTP_CODE" = "400" ]; then
        print_success "Invalid control status rejected (400)"
    else
        print_failure "Invalid status should be rejected (got HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No control for invalid status test"
fi

# =============================================================================
# Cleanup
# =============================================================================

print_header "Cleanup"

if [ -n "$ASSET_ID" ]; then
    do_request DELETE "/api/v1/assets/${ASSET_ID}" "" "$(auth_header)"
fi
if [ -n "$ASSESSMENT_ID" ]; then
    do_request DELETE "/api/v1/compliance/assessments/${ASSESSMENT_ID}" "" "$(auth_header)"
fi
if [ -n "$FRAMEWORK_ID" ]; then
    do_request DELETE "/api/v1/compliance/frameworks/${FRAMEWORK_ID}" "" "$(auth_header)"
fi
if [ -n "$FRAMEWORK_ID_2" ]; then
    do_request DELETE "/api/v1/compliance/frameworks/${FRAMEWORK_ID_2}" "" "$(auth_header)"
fi
print_success "Cleaned up test data"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}Compliance Framework E2E Test Summary${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASSED}${NC}"
echo -e "  Failed:  ${RED}${FAILED}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIPPED}${NC}"
echo -e "  Total Tests: $((PASSED + FAILED + SKIPPED))"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All compliance tests passed!${NC}"
    exit 0
else
    echo -e "  ${RED}Some compliance tests failed!${NC}"
    exit 1
fi
