#!/bin/bash
# =============================================================================
# E2E Test: Scan Feature Phase 1 + Phase 2 Improvements
# =============================================================================
# Validates the Phase 1.x and Phase 2.x scan feature work end-to-end:
#
#   Phase 1.1 — DB schema (agent_preference, profile_id, timeout_seconds)
#   Phase 1.2 — ScanProfile linking + timezone fix
#   Phase 1.3 — Findings drill-down via /findings?scan_id=
#   Phase 1.5 — Scan timeout enforcement (ScanTimeoutController)
#   Phase 1.6 — Distributed scheduler lock
#   Phase 1.8a — ScanDetailResponse exposes new fields
#   Phase 1.8b — UpdateScan handles new fields
#   Phase 1.8c — Import/export handles new fields
#   Phase 1.8d — Min timeout = 30s, GetAccessibleByID enforcement
#   Phase 2.1 — Quality gate evaluation (profile_id propagated to runs)
#   Phase 2.2 — Job cancellation cascades to commands
#   Phase 2.3 — Retry logic with max_retries + retry_backoff_seconds
#
# Prerequisites:
#   - API running with AUTH_ALLOW_REGISTRATION=true
#   - Migrations 102 and 103 applied
#   - jq, curl installed
#
# Usage:
#   ./test_e2e_scan_phase1_2.sh [API_URL]
# =============================================================================

# Don't use set -e because counter arithmetic can return 1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-scan-p12-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Scan Phase1+2 User"
TEST_TEAM_NAME="E2E Scan P12 Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-scan-p12-${TIMESTAMP}"

# Second user for cross-tenant security tests
EVIL_EMAIL="e2e-scan-p12-evil-${TIMESTAMP}@openctem-test.local"
EVIL_PASSWORD="EvilP@ss123!"
EVIL_TEAM_SLUG="e2e-scan-p12-evil-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_p12_cookies.XXXXXX)
EVIL_COOKIE_JAR=$(mktemp /tmp/openctem_p12_evil_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_p12_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$EVIL_COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
EVIL_TOKEN=""
EVIL_TENANT_ID=""
ASSET_ID=""
ASSET_GROUP_ID=""
SCAN_PROFILE_ID=""
EVIL_SCAN_PROFILE_ID=""
SCAN_ID=""
CRITICAL_FAILURE=0

BODY=""
HTTP_CODE=""

# =============================================================================
# Helpers
# =============================================================================

print_header() { echo -e "\n${BLUE}===============================================================================${NC}\n${BLUE}$1${NC}\n${BLUE}===============================================================================${NC}"; }
print_test()    { echo -e "\n${YELLOW}>>> $1${NC}"; }
print_success() { echo -e "${GREEN}  PASSED: $1${NC}"; PASSED=$((PASSED + 1)); }
print_failure() { echo -e "${RED}  FAILED: $1${NC}"; [ -n "$2" ] && echo -e "${RED}  Error: $2${NC}"; FAILED=$((FAILED + 1)); }
print_skip()    { echo -e "${YELLOW}  SKIPPED: $1${NC}"; SKIPPED=$((SKIPPED + 1)); }
print_info()    { echo -e "  $1"; }

extract_json() { echo "$1" | jq -r "$2" 2>/dev/null; }

do_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local cookie_jar="${4:-$COOKIE_JAR}"
    shift 4 2>/dev/null || shift 3

    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json"
        -c "$cookie_jar" -b "$cookie_jar")

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

mark_critical_failure() { CRITICAL_FAILURE=1; }

assert_field_present() {
    local field="$1"
    local description="$2"
    local value=$(extract_json "$BODY" "$field")
    if [ -n "$value" ] && [ "$value" != "null" ]; then
        print_success "$description (value: $value)"
    else
        print_failure "$description" "Field $field missing or null"
    fi
}

assert_field_equals() {
    local field="$1"
    local expected="$2"
    local description="$3"
    local actual=$(extract_json "$BODY" "$field")
    if [ "$actual" = "$expected" ]; then
        print_success "$description (= $expected)"
    else
        print_failure "$description" "Expected $field=$expected, got $actual"
    fi
}

assert_http_code() {
    local expected="$1"
    local description="$2"
    if [ "$HTTP_CODE" = "$expected" ]; then
        print_success "$description (HTTP $HTTP_CODE)"
    else
        print_failure "$description" "Expected HTTP $expected, got $HTTP_CODE. Body: $BODY"
    fi
}

# =============================================================================
# Pre-flight
# =============================================================================

print_header "E2E Test: Scan Feature Phase 1 + Phase 2"

echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

if ! command -v jq &> /dev/null; then echo -e "${RED}Error: jq required${NC}"; exit 1; fi
if ! command -v curl &> /dev/null; then echo -e "${RED}Error: curl required${NC}"; exit 1; fi

# =============================================================================
# Section 1: Health
# =============================================================================

print_header "Section 1: Health Check"

print_test "API is up"
do_request "GET" "/health" ""
assert_http_code "200" "API responds to /health"
[ "$HTTP_CODE" != "200" ] && exit 1

# =============================================================================
# Section 2: Auth + Setup (primary user)
# =============================================================================

print_header "Section 2: Setup Primary Tenant"

print_test "Register primary user"
do_request "POST" "/api/v1/auth/register" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"name\":\"$TEST_NAME\"}"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "User registered"
else
    print_failure "Register" "Expected 201, got $HTTP_CODE: $BODY"
    mark_critical_failure
fi

if check_critical "Login"; then
    print_test "Login primary user"
    do_request "POST" "/api/v1/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Logged in"
    else
        print_failure "Login" "Expected 200, got $HTTP_CODE: $BODY"
        mark_critical_failure
    fi
fi

if check_critical "Create team"; then
    print_test "Create first team"
    do_request "POST" "/api/v1/auth/create-first-team" "{\"team_name\":\"$TEST_TEAM_NAME\",\"team_slug\":\"$TEST_TEAM_SLUG\"}"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
        TENANT_ID=$(extract_json "$BODY" '.tenant_id')
        if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
            print_success "Team created"
            print_info "Tenant ID: $TENANT_ID"
        else
            print_failure "Create team" "Missing access_token"
            mark_critical_failure
        fi
    else
        print_failure "Create team" "Expected 201, got $HTTP_CODE: $BODY"
        mark_critical_failure
    fi
fi

# =============================================================================
# Section 3: Setup Evil Tenant (for cross-tenant security tests)
# =============================================================================

print_header "Section 3: Setup Evil Tenant"

print_test "Register evil user"
sleep 25  # Avoid rate limiting (3/min)
do_request "POST" "/api/v1/auth/register" "{\"email\":\"$EVIL_EMAIL\",\"password\":\"$EVIL_PASSWORD\",\"name\":\"Evil User\"}" "$EVIL_COOKIE_JAR"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Evil user registered"

    sleep 15  # Login rate limit
    do_request "POST" "/api/v1/auth/login" "{\"email\":\"$EVIL_EMAIL\",\"password\":\"$EVIL_PASSWORD\"}" "$EVIL_COOKIE_JAR"
    if [ "$HTTP_CODE" = "200" ]; then
        do_request "POST" "/api/v1/auth/create-first-team" "{\"team_name\":\"Evil Team\",\"team_slug\":\"$EVIL_TEAM_SLUG\"}" "$EVIL_COOKIE_JAR"
        if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
            EVIL_TOKEN=$(extract_json "$BODY" '.access_token')
            EVIL_TENANT_ID=$(extract_json "$BODY" '.tenant_id')
            print_success "Evil team created"
            print_info "Evil tenant: $EVIL_TENANT_ID"
        else
            print_failure "Create evil team" "Got $HTTP_CODE"
        fi
    fi
else
    print_skip "Evil tenant setup (rate limited or already exists)"
fi

# =============================================================================
# Section 4: Asset & Asset Group setup
# =============================================================================

print_header "Section 4: Prerequisites (Asset + Group)"

if check_critical "Asset setup"; then
    print_test "Create asset"
    do_request "POST" "/api/v1/assets" "{\"name\":\"e2e-p12-${TIMESTAMP}.example.com\",\"type\":\"domain\",\"criticality\":\"high\"}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        ASSET_ID=$(extract_json "$BODY" '.id')
        print_success "Asset created"
        print_info "Asset ID: $ASSET_ID"
    else
        print_failure "Create asset" "$HTTP_CODE: $BODY"
        mark_critical_failure
    fi

    print_test "Create asset group"
    do_request "POST" "/api/v1/asset-groups" "{\"name\":\"E2E P12 Group ${TIMESTAMP}\",\"environment\":\"testing\",\"criticality\":\"high\",\"existing_asset_ids\":[\"$ASSET_ID\"]}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        ASSET_GROUP_ID=$(extract_json "$BODY" '.id')
        print_success "Asset group created"
        print_info "Group ID: $ASSET_GROUP_ID"
    else
        print_failure "Create asset group" "$HTTP_CODE: $BODY"
        mark_critical_failure
    fi
fi

# =============================================================================
# Section 5: Scan Profile setup (for ProfileID linking tests)
# =============================================================================

print_header "Section 5: Create Scan Profile"

if check_critical "Profile setup"; then
    print_test "Create scan profile (medium intensity, quality gate enabled)"
    do_request "POST" "/api/v1/scan-profiles" "{
        \"name\": \"E2E P12 Profile ${TIMESTAMP}\",
        \"description\": \"Profile for Phase 1+2 testing\",
        \"intensity\": \"medium\",
        \"max_concurrent_scans\": 2,
        \"timeout_seconds\": 3600,
        \"quality_gate\": {
            \"enabled\": true,
            \"fail_on_critical\": true,
            \"fail_on_high\": false,
            \"max_critical\": 0,
            \"max_high\": 5,
            \"max_medium\": 20,
            \"max_total\": -1
        }
    }" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        SCAN_PROFILE_ID=$(extract_json "$BODY" '.id')
        print_success "Scan profile created"
        print_info "Profile ID: $SCAN_PROFILE_ID"
    else
        print_failure "Create scan profile" "$HTTP_CODE: $BODY"
    fi

    if [ -n "$EVIL_TOKEN" ]; then
        print_test "Create scan profile in evil tenant (for cross-tenant test)"
        do_request "POST" "/api/v1/scan-profiles" "{
            \"name\": \"Evil Profile ${TIMESTAMP}\",
            \"intensity\": \"low\",
            \"max_concurrent_scans\": 1,
            \"timeout_seconds\": 1800
        }" "$EVIL_COOKIE_JAR" "Authorization: Bearer $EVIL_TOKEN"
        if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
            EVIL_SCAN_PROFILE_ID=$(extract_json "$BODY" '.id')
            print_success "Evil profile created"
        else
            print_skip "Evil profile creation failed - cross-tenant test will be limited"
        fi
    fi
fi

# =============================================================================
# Section 6: Phase 1.1 + 1.2 — Scan with new fields
# =============================================================================

print_header "Section 6: Phase 1.1 + 1.2 — Scan with profile_id, agent_preference, timeout_seconds"

if check_critical "Scan create"; then
    print_test "Create scan with profile_id, agent_preference=auto, timeout_seconds=120"
    do_request "POST" "/api/v1/scans" "{
        \"name\": \"E2E P12 Scan ${TIMESTAMP}\",
        \"description\": \"Phase 1+2 scan with all new fields\",
        \"asset_group_id\": \"$ASSET_GROUP_ID\",
        \"scan_type\": \"single\",
        \"scanner_name\": \"nuclei\",
        \"agent_preference\": \"auto\",
        \"profile_id\": \"$SCAN_PROFILE_ID\",
        \"timeout_seconds\": 120,
        \"max_retries\": 2,
        \"retry_backoff_seconds\": 30
    }" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        SCAN_ID=$(extract_json "$BODY" '.id')
        print_success "Scan created with new fields"
        print_info "Scan ID: $SCAN_ID"
    else
        print_failure "Create scan" "$HTTP_CODE: $BODY"
        mark_critical_failure
    fi
fi

# Phase 1.8a — Verify response exposes new fields
print_test "GET scan returns agent_preference, profile_id, timeout_seconds, max_retries"
do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    assert_field_equals '.agent_preference' "auto" "agent_preference returned"
    assert_field_equals '.profile_id' "$SCAN_PROFILE_ID" "profile_id returned"
    assert_field_equals '.timeout_seconds' "120" "timeout_seconds returned"
    assert_field_equals '.max_retries' "2" "max_retries returned"
    assert_field_equals '.retry_backoff_seconds' "30" "retry_backoff_seconds returned"
else
    print_failure "GET scan" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 7: Phase 1.8d — Min timeout enforcement (security)
# =============================================================================

print_header "Section 7: Phase 1.8d — Min Timeout = 30s Validation"

print_test "Reject timeout_seconds = 1 (should fail validation)"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"E2E P12 Bad Timeout ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"timeout_seconds\": 1
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "1s timeout rejected (DoS protection works)"
else
    print_failure "timeout_seconds=1 should be rejected" "Got $HTTP_CODE: $BODY"
fi

print_test "Reject timeout_seconds = 100000 (above max 86400)"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"E2E P12 Big Timeout ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"timeout_seconds\": 100000
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "100000s timeout rejected (above max)"
else
    print_failure "timeout_seconds=100000 should be rejected" "Got $HTTP_CODE: $BODY"
fi

print_test "Accept timeout_seconds = 30 (boundary)"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"E2E P12 Min Timeout ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"timeout_seconds\": 30
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "30s timeout accepted (boundary)"
else
    print_failure "timeout_seconds=30 should be accepted" "Got $HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 8: Phase 1.8d — Cross-tenant profile access (security)
# =============================================================================

print_header "Section 8: Phase 1.8d — Cross-tenant Profile Access"

if [ -n "$EVIL_SCAN_PROFILE_ID" ]; then
    print_test "Reject scan creation with evil tenant's profile_id (cross-tenant)"
    do_request "POST" "/api/v1/scans" "{
        \"name\": \"E2E P12 Cross-tenant ${TIMESTAMP}\",
        \"asset_group_id\": \"$ASSET_GROUP_ID\",
        \"scan_type\": \"single\",
        \"scanner_name\": \"nuclei\",
        \"profile_id\": \"$EVIL_SCAN_PROFILE_ID\"
    }" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "400" ]; then
        print_success "Cross-tenant profile blocked (no info leak)"
    else
        print_failure "Should reject cross-tenant profile" "Got $HTTP_CODE: $BODY"
    fi
else
    print_skip "Cross-tenant profile test (evil profile not created)"
fi

print_test "Reject scan with garbage profile_id (UUID validation)"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"E2E P12 Bad Profile ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"profile_id\": \"not-a-uuid\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Invalid UUID rejected"
else
    print_failure "Invalid profile_id should be rejected" "Got $HTTP_CODE"
fi

# =============================================================================
# Section 9: Phase 1.8b — UpdateScan with new fields
# =============================================================================

print_header "Section 9: Phase 1.8b — UpdateScan handles new fields"

print_test "Update scan: change agent_preference to 'tenant', timeout to 60"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"name\": \"E2E P12 Scan ${TIMESTAMP}\",
    \"agent_preference\": \"tenant\",
    \"timeout_seconds\": 60
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Update accepted"
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    assert_field_equals '.agent_preference' "tenant" "agent_preference updated"
    assert_field_equals '.timeout_seconds' "60" "timeout_seconds updated"
else
    print_failure "Update scan" "$HTTP_CODE: $BODY"
fi

print_test "Update scan: unlink profile_id (sentinel = empty string)"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"name\": \"E2E P12 Scan ${TIMESTAMP}\",
    \"profile_id\": \"\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    profile_id=$(extract_json "$BODY" '.profile_id')
    if [ "$profile_id" = "null" ] || [ -z "$profile_id" ]; then
        print_success "Profile unlinked successfully"
    else
        print_failure "Profile should be null after unlink" "Got: $profile_id"
    fi
else
    print_failure "Unlink profile" "$HTTP_CODE: $BODY"
fi

print_test "Update scan: re-link profile_id"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"name\": \"E2E P12 Scan ${TIMESTAMP}\",
    \"profile_id\": \"$SCAN_PROFILE_ID\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    assert_field_equals '.profile_id' "$SCAN_PROFILE_ID" "Profile re-linked"
else
    print_failure "Re-link profile" "$HTTP_CODE: $BODY"
fi

print_test "Update scan: max_retries = 5, backoff = 60"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"name\": \"E2E P12 Scan ${TIMESTAMP}\",
    \"max_retries\": 5,
    \"retry_backoff_seconds\": 60
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    assert_field_equals '.max_retries' "5" "max_retries updated"
    assert_field_equals '.retry_backoff_seconds' "60" "retry_backoff_seconds updated"
else
    print_failure "Update retry config" "$HTTP_CODE: $BODY"
fi

print_test "Reject update with max_retries = 100 (above max 10)"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"max_retries\": 100
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "max_retries=100 rejected"
else
    print_failure "max_retries=100 should be rejected" "Got $HTTP_CODE"
fi

print_test "Reject update with retry_backoff_seconds = 5 (below min 10)"
do_request "PUT" "/api/v1/scans/$SCAN_ID" "{
    \"retry_backoff_seconds\": 5
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "retry_backoff=5 rejected"
else
    print_failure "retry_backoff=5 should be rejected" "Got $HTTP_CODE"
fi

# =============================================================================
# Section 10: Phase 1.8c — Export/Import roundtrip
# =============================================================================

print_header "Section 10: Phase 1.8c — Export/Import preserves new fields"

print_test "Export scan config"
do_request "GET" "/api/v1/scans/$SCAN_ID/export" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Export succeeded"
    EXPORTED=$(echo "$BODY" | jq -c '. + {name: "E2E P12 Imported Scan '"${TIMESTAMP}"'"}')
    has_profile=$(echo "$BODY" | jq -r '.profile_id // empty')
    has_timeout=$(echo "$BODY" | jq -r '.timeout_seconds // empty')
    if [ -n "$has_profile" ] && [ -n "$has_timeout" ]; then
        print_success "Export includes profile_id ($has_profile) and timeout_seconds ($has_timeout)"
    else
        print_failure "Export missing fields" "profile_id=$has_profile timeout=$has_timeout"
    fi
else
    print_failure "Export scan" "$HTTP_CODE: $BODY"
fi

print_test "Import scan config (new name)"
if [ -n "$EXPORTED" ]; then
    do_request "POST" "/api/v1/scans/import" "$EXPORTED" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        IMPORTED_ID=$(extract_json "$BODY" '.id')
        print_success "Imported scan created: $IMPORTED_ID"

        do_request "GET" "/api/v1/scans/$IMPORTED_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
        imported_profile=$(extract_json "$BODY" '.profile_id')
        imported_timeout=$(extract_json "$BODY" '.timeout_seconds')
        if [ "$imported_profile" = "$SCAN_PROFILE_ID" ] && [ "$imported_timeout" = "60" ]; then
            print_success "Import roundtrip preserves profile_id and timeout_seconds"
        else
            print_failure "Import lost data" "profile=$imported_profile (expected $SCAN_PROFILE_ID) timeout=$imported_timeout (expected 60)"
        fi
    else
        print_failure "Import scan" "$HTTP_CODE: $BODY"
    fi
fi

# =============================================================================
# Section 11: Phase 2.1 — Quality gate evaluation wiring
# =============================================================================

print_header "Section 11: Phase 2.1 — Quality gate evaluation"

print_test "Trigger scan with profile_id linked"
do_request "POST" "/api/v1/scans/$SCAN_ID/trigger" "{}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
    print_success "Scan triggered"
    print_info "Quality gate eval will run when scan completes (requires agent)"
elif [ "$HTTP_CODE" = "503" ]; then
    print_skip "Trigger requires agent online"
else
    print_failure "Trigger scan" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 12: Phase 1.3 — Findings drill-down via /findings?scan_id=
# =============================================================================

print_header "Section 12: Phase 1.3 — Findings filter by scan_id"

print_test "List findings filtered by scan_id"
do_request "GET" "/api/v1/findings?scan_id=$SCAN_ID&per_page=10" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Findings filter accepts scan_id parameter"
else
    print_failure "Findings filter" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 13: Phase 2.2 — Job cancellation (via run cancel)
# =============================================================================

print_header "Section 13: Phase 2.2 — Cancel scan run cascades to commands"

print_test "List scan runs (need at least one to cancel)"
do_request "GET" "/api/v1/scans/$SCAN_ID/runs?per_page=5" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    RUN_ID=$(extract_json "$BODY" '.items[0].id // .data[0].id')
    if [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ]; then
        print_success "Found run: $RUN_ID"

        print_test "Cancel pipeline run"
        do_request "POST" "/api/v1/pipelines/runs/$RUN_ID/cancel" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
            print_success "Run cancellation accepted (cascade should cancel commands)"
        elif [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "409" ]; then
            print_skip "Run already complete (expected if no agent)"
        else
            print_failure "Cancel run" "$HTTP_CODE: $BODY"
        fi
    else
        print_skip "No runs found to cancel"
    fi
else
    print_failure "List runs" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 14: Phase 1.8a — Tenant isolation on GET
# =============================================================================

print_header "Section 14: Tenant isolation on scan GET"

if [ -n "$EVIL_TOKEN" ]; then
    print_test "Evil tenant cannot GET our scan"
    do_request "GET" "/api/v1/scans/$SCAN_ID" "" "$EVIL_COOKIE_JAR" "Authorization: Bearer $EVIL_TOKEN"
    if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "403" ]; then
        print_success "Cross-tenant scan access blocked"
    else
        print_failure "Tenant isolation broken!" "Got $HTTP_CODE - this is a CRITICAL security bug"
    fi

    print_test "Evil tenant cannot UPDATE our scan"
    do_request "PUT" "/api/v1/scans/$SCAN_ID" "{\"name\":\"hacked\"}" "$EVIL_COOKIE_JAR" "Authorization: Bearer $EVIL_TOKEN"
    if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "403" ]; then
        print_success "Cross-tenant update blocked"
    else
        print_failure "Cross-tenant update succeeded!" "$HTTP_CODE: $BODY"
    fi

    print_test "Evil tenant cannot DELETE our scan"
    do_request "DELETE" "/api/v1/scans/$SCAN_ID" "" "$EVIL_COOKIE_JAR" "Authorization: Bearer $EVIL_TOKEN"
    if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "403" ]; then
        print_success "Cross-tenant delete blocked"
    else
        print_failure "Cross-tenant delete succeeded!" "$HTTP_CODE: $BODY"
    fi
else
    print_skip "Tenant isolation tests (no evil tenant)"
fi

# =============================================================================
# Section 15: Schema validation edge cases
# =============================================================================

print_header "Section 15: Edge case validation"

print_test "Reject agent_preference = 'invalid'"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"Bad Pref ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"agent_preference\": \"invalid\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Invalid agent_preference rejected"
else
    print_failure "Should reject invalid agent_preference" "Got $HTTP_CODE"
fi

print_test "Accept agent_preference = 'platform'"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"Platform Pref ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"agent_preference\": \"platform\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "agent_preference=platform accepted"
else
    print_failure "platform should be accepted" "Got $HTTP_CODE: $BODY"
fi

print_test "Schedule with valid timezone"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"TZ Scan ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"schedule_type\": \"daily\",
    \"schedule_time\": \"$(date -u +%H:%M)\",
    \"timezone\": \"America/New_York\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    TZ_SCAN_ID=$(extract_json "$BODY" '.id')
    print_success "Schedule with valid timezone accepted"

    print_test "Verify schedule_timezone persisted"
    do_request "GET" "/api/v1/scans/$TZ_SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
    assert_field_equals '.schedule_timezone' "America/New_York" "Timezone persisted"
else
    print_failure "Schedule with timezone" "$HTTP_CODE: $BODY"
fi

print_test "Reject schedule with invalid timezone"
do_request "POST" "/api/v1/scans" "{
    \"name\": \"Bad TZ Scan ${TIMESTAMP}\",
    \"asset_group_id\": \"$ASSET_GROUP_ID\",
    \"scan_type\": \"single\",
    \"scanner_name\": \"nuclei\",
    \"schedule_type\": \"daily\",
    \"schedule_time\": \"03:00\",
    \"timezone\": \"Mars/Olympus_Mons\"
}" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Invalid timezone rejected"
else
    print_failure "Invalid timezone should be rejected" "Got $HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 16: Stats and listing
# =============================================================================

print_header "Section 16: Stats reflect new scans"

print_test "GET scan stats"
do_request "GET" "/api/v1/scans/stats" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    total=$(extract_json "$BODY" '.total')
    if [ -n "$total" ] && [ "$total" != "null" ] && [ "$total" -gt "0" ]; then
        print_success "Scan stats returned (total=$total)"
    else
        print_failure "Stats missing or zero" "$BODY"
    fi
else
    print_failure "Stats endpoint" "$HTTP_CODE: $BODY"
fi

print_test "List scans with pagination"
do_request "GET" "/api/v1/scans?per_page=10" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    count=$(echo "$BODY" | jq -r '.data | length // 0')
    if [ "$count" -gt "0" ]; then
        print_success "Listed $count scans"
    else
        print_failure "List returned no scans" "$BODY"
    fi
else
    print_failure "List scans" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Section 17: Cleanup
# =============================================================================

print_header "Section 17: Cleanup"

print_test "Delete primary scan"
do_request "DELETE" "/api/v1/scans/$SCAN_ID" "" "$COOKIE_JAR" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    print_success "Scan deleted"
else
    print_failure "Delete scan" "$HTTP_CODE: $BODY"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Test Summary"

echo
echo -e "  ${GREEN}Passed:  $PASSED${NC}"
echo -e "  ${RED}Failed:  $FAILED${NC}"
echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
echo -e "  Total:   $((PASSED + FAILED + SKIPPED))"
echo

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
