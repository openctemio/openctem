#!/usr/bin/env bash
#
# test_notification_api.sh - Comprehensive test suite for the Notification API endpoints.
#
# Usage:
#   ./test_notification_api.sh
#   AUTH_TOKEN="eyJ..." ./test_notification_api.sh
#   BASE_URL="http://api.example.com" ./test_notification_api.sh
#
# Requirements:
#   - curl
#   - jq
#   - A running OpenCTEM API instance
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

BASE_URL="${BASE_URL:-http://localhost:8080}"
AUTH_TOKEN="${AUTH_TOKEN:-}"
LOGIN_EMAIL="${LOGIN_EMAIL:-admin@openctem.io}"
LOGIN_PASSWORD="${LOGIN_PASSWORD:-admin123}"

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# Counters
PASSED=0
FAILED=0
TOTAL=0

# =============================================================================
# Helper Functions
# =============================================================================

log_pass() {
    local test_name="$1"
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
}

log_fail() {
    local test_name="$1"
    local details="${2:-}"
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "  ${RED}[FAIL]${NC} ${test_name}"
    if [[ -n "$details" ]]; then
        echo -e "         ${RED}${details}${NC}"
    fi
}

log_info() {
    local message="$1"
    echo -e "  ${YELLOW}[INFO]${NC} ${message}"
}

log_section() {
    local title="$1"
    echo ""
    echo -e "${CYAN}--- ${title} ---${NC}"
}

# Extract HTTP status code from curl response.
# Expects the last line of the response to be the status code (via -w).
get_status() {
    echo "$1" | tail -n1
}

# Extract response body (everything except the last line which is the status code).
get_body() {
    echo "$1" | sed '$d'
}

# Assert HTTP status code matches expected.
assert_status() {
    local response="$1"
    local expected="$2"
    local test_name="$3"
    local status
    status=$(get_status "$response")

    if [[ "$status" == "$expected" ]]; then
        log_pass "${test_name} (HTTP ${expected})"
        return 0
    else
        local body
        body=$(get_body "$response")
        log_fail "${test_name}" "Expected HTTP ${expected}, got ${status}. Body: $(echo "$body" | head -c 200)"
        return 1
    fi
}

# Assert HTTP status is one of several expected values.
assert_status_one_of() {
    local response="$1"
    shift
    local test_name="${!#}" # last argument
    local expected_codes=("${@:1:$#-1}")
    local status
    status=$(get_status "$response")

    for code in "${expected_codes[@]}"; do
        if [[ "$status" == "$code" ]]; then
            log_pass "${test_name} (HTTP ${status})"
            return 0
        fi
    done

    local body
    body=$(get_body "$response")
    log_fail "${test_name}" "Expected HTTP one of [${expected_codes[*]}], got ${status}. Body: $(echo "$body" | head -c 200)"
    return 1
}

# Assert a JSON field exists and optionally matches an expected value.
# Usage:
#   assert_json_field "$body" ".count" "" "T02: count field exists"
#   assert_json_field "$body" ".in_app_enabled" "true" "T03: in_app_enabled is true"
assert_json_field() {
    local body="$1"
    local field="$2"
    local expected_value="$3"
    local test_name="$4"

    local actual
    actual=$(echo "$body" | jq -r "$field" 2>/dev/null)

    if [[ "$actual" == "null" ]] && [[ -z "$expected_value" ]]; then
        # Field doesn't exist and we just wanted to check existence
        log_fail "${test_name}" "Field ${field} is null or missing"
        return 1
    fi

    if [[ -z "$expected_value" ]]; then
        # Just check existence (non-null)
        if [[ "$actual" != "null" ]]; then
            log_pass "${test_name}"
            return 0
        else
            log_fail "${test_name}" "Field ${field} is null"
            return 1
        fi
    fi

    if [[ "$actual" == "$expected_value" ]]; then
        log_pass "${test_name}"
        return 0
    else
        log_fail "${test_name}" "Field ${field}: expected '${expected_value}', got '${actual}'"
        return 1
    fi
}

# Assert a JSON field is a number >= a given value.
assert_json_gte() {
    local body="$1"
    local field="$2"
    local min_value="$3"
    local test_name="$4"

    local actual
    actual=$(echo "$body" | jq -r "$field" 2>/dev/null)

    if [[ "$actual" == "null" ]]; then
        log_fail "${test_name}" "Field ${field} is null"
        return 1
    fi

    if [[ "$actual" -ge "$min_value" ]] 2>/dev/null; then
        log_pass "${test_name}"
        return 0
    else
        log_fail "${test_name}" "Field ${field}: expected >= ${min_value}, got '${actual}'"
        return 1
    fi
}

# Make an API request with authentication.
# Usage: api_request METHOD PATH [BODY]
# Returns: response body + status code on last line
api_request() {
    local method="$1"
    local path="$2"
    local body="${3:-}"

    local curl_args=(
        -s
        -X "$method"
        -H "Content-Type: application/json"
        -H "Authorization: Bearer ${AUTH_TOKEN}"
        -w "\n%{http_code}"
    )

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
    fi

    curl "${curl_args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo -e "\n000"
}

# Make an API request WITHOUT authentication.
api_request_no_auth() {
    local method="$1"
    local path="$2"

    curl -s -X "$method" \
        -H "Content-Type: application/json" \
        -w "\n%{http_code}" \
        "${BASE_URL}${path}" 2>/dev/null || echo -e "\n000"
}

# =============================================================================
# Login Helper
# =============================================================================

login() {
    log_section "Authentication"

    if [[ -n "$AUTH_TOKEN" ]]; then
        log_info "Using AUTH_TOKEN from environment"
        return 0
    fi

    log_info "Attempting login with ${LOGIN_EMAIL}..."

    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"${LOGIN_EMAIL}\", \"password\": \"${LOGIN_PASSWORD}\"}" \
        -w "\n%{http_code}" \
        "${BASE_URL}/api/v1/auth/login" 2>/dev/null || echo -e "\n000")

    local status
    status=$(get_status "$response")
    local body
    body=$(get_body "$response")

    if [[ "$status" == "200" ]]; then
        AUTH_TOKEN=$(echo "$body" | jq -r '.token // .access_token // .data.token // .data.access_token // empty' 2>/dev/null)
        if [[ -z "$AUTH_TOKEN" ]]; then
            echo -e "${RED}Login succeeded but could not extract token from response.${NC}"
            echo "Response: $(echo "$body" | head -c 500)"
            exit 1
        fi
        log_info "Login successful, token obtained"
        return 0
    else
        echo -e "${RED}Login failed (HTTP ${status}). Set AUTH_TOKEN env var manually.${NC}"
        echo "Response: $(echo "$body" | head -c 500)"
        exit 1
    fi
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight() {
    log_section "Pre-flight Checks"

    # Check dependencies
    for cmd in curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}Required command '${cmd}' not found. Please install it.${NC}"
            exit 1
        fi
    done
    log_info "Dependencies OK (curl, jq)"

    # Check API reachability
    local health_status
    health_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" 2>/dev/null || echo "000")
    if [[ "$health_status" == "200" ]]; then
        log_info "API reachable at ${BASE_URL}"
    else
        echo -e "${RED}API not reachable at ${BASE_URL}/health (HTTP ${health_status})${NC}"
        exit 1
    fi
}

# =============================================================================
# Test Cases
# =============================================================================

test_t01_list_notifications() {
    log_section "T01: List notifications"

    local response
    response=$(api_request GET "/api/v1/notifications")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T01: List notifications" || true
    assert_json_field "$body" ".data" "" "T01: response has 'data' field" || true
    assert_json_field "$body" ".total" "" "T01: response has 'total' field" || true
    assert_json_field "$body" ".page" "" "T01: response has 'page' field" || true
    assert_json_field "$body" ".per_page" "" "T01: response has 'per_page' field" || true
    assert_json_field "$body" ".total_pages" "" "T01: response has 'total_pages' field" || true
}

test_t02_unread_count() {
    log_section "T02: Get unread count"

    local response
    response=$(api_request GET "/api/v1/notifications/unread-count")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T02: Get unread count" || true
    assert_json_gte "$body" ".count" "0" "T02: count >= 0" || true
}

test_t03_get_default_preferences() {
    log_section "T03: Get default preferences"

    local response
    response=$(api_request GET "/api/v1/notifications/preferences")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T03: Get preferences" || true
    assert_json_field "$body" ".in_app_enabled" "true" "T03: in_app_enabled is true (default)" || true
    assert_json_field "$body" ".email_digest" "none" "T03: email_digest is 'none' (default)" || true
}

test_t04_update_preferences_valid() {
    log_section "T04: Update preferences (valid)"

    local payload='{"in_app_enabled": false, "email_digest": "daily", "min_severity": "high"}'
    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T04: Update preferences" || true
    assert_json_field "$body" ".in_app_enabled" "false" "T04: in_app_enabled is false" || true
    assert_json_field "$body" ".email_digest" "daily" "T04: email_digest is 'daily'" || true
    assert_json_field "$body" ".min_severity" "high" "T04: min_severity is 'high'" || true
}

test_t05_update_preferences_invalid_digest() {
    log_section "T05: Update preferences (invalid email_digest)"

    local payload='{"email_digest": "hourly"}'
    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")

    assert_status_one_of "$response" "400" "422" "T05: Reject invalid email_digest" || true
}

test_t06_update_preferences_invalid_severity() {
    log_section "T06: Update preferences (invalid min_severity)"

    local payload='{"min_severity": "extreme"}'
    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")

    assert_status_one_of "$response" "400" "422" "T06: Reject invalid min_severity" || true
}

test_t07_update_preferences_too_many_muted() {
    log_section "T07: Update preferences (muted_types > 50)"

    # Generate array of 51 items
    local items=""
    for i in $(seq 1 51); do
        if [[ -n "$items" ]]; then
            items="${items},"
        fi
        items="${items}\"type_${i}\""
    done
    local payload="{\"muted_types\": [${items}]}"

    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")

    assert_status_one_of "$response" "400" "422" "T07: Reject muted_types > 50" || true
}

test_t08_update_preferences_partial() {
    log_section "T08: Update preferences (partial update)"

    local payload='{"email_digest": "weekly"}'
    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T08: Partial update" || true
    assert_json_field "$body" ".email_digest" "weekly" "T08: email_digest is 'weekly'" || true
    assert_json_field "$body" ".in_app_enabled" "false" "T08: in_app_enabled still false (from T04)" || true
}

test_t09_reset_preferences() {
    log_section "T09: Reset preferences"

    local payload='{"in_app_enabled": true, "email_digest": "none", "min_severity": "", "muted_types": []}'
    local response
    response=$(api_request PUT "/api/v1/notifications/preferences" "$payload")

    assert_status "$response" "200" "T09: Reset preferences" || true
}

test_t10_mark_all_as_read() {
    log_section "T10: Mark all as read"

    local response
    response=$(api_request POST "/api/v1/notifications/read-all")

    assert_status_one_of "$response" "200" "204" "T10: Mark all as read" || true
}

test_t11_mark_single_invalid_id() {
    log_section "T11: Mark single as read (invalid ID)"

    local response
    response=$(api_request PATCH "/api/v1/notifications/invalid-uuid/read")

    assert_status "$response" "400" "T11: Reject invalid UUID" || true
}

test_t12_mark_single_nonexistent() {
    log_section "T12: Mark single as read (nonexistent)"

    local response
    response=$(api_request PATCH "/api/v1/notifications/00000000-0000-0000-0000-000000000000/read")

    assert_status "$response" "404" "T12: 404 for nonexistent notification" || true
}

test_t13_list_with_filters() {
    log_section "T13: List with filters"

    local response

    response=$(api_request GET "/api/v1/notifications?severity=critical")
    assert_status "$response" "200" "T13a: Filter by severity=critical" || true

    response=$(api_request GET "/api/v1/notifications?type=finding_new")
    assert_status "$response" "200" "T13b: Filter by type=finding_new" || true

    response=$(api_request GET "/api/v1/notifications?is_read=false")
    assert_status "$response" "200" "T13c: Filter by is_read=false" || true
}

test_t14_list_with_pagination() {
    log_section "T14: List with pagination"

    local response
    response=$(api_request GET "/api/v1/notifications?page=1&per_page=5")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T14: Paginated list" || true
    assert_json_field "$body" ".per_page" "5" "T14: per_page is 5" || true
}

test_t15_list_invalid_per_page() {
    log_section "T15: List with invalid per_page (clamped)"

    local response
    response=$(api_request GET "/api/v1/notifications?per_page=200")
    local body
    body=$(get_body "$response")

    assert_status "$response" "200" "T15: Accept large per_page (clamped)" || true

    # per_page=200 is > 100, so the handler ignores it and uses default (20)
    # The handler only accepts parsed > 0 && parsed <= 100
    local per_page
    per_page=$(echo "$body" | jq -r '.per_page' 2>/dev/null)
    if [[ "$per_page" -le 100 ]] 2>/dev/null; then
        log_pass "T15: per_page clamped to <= 100 (got ${per_page})"
    else
        log_fail "T15: per_page not clamped" "Expected <= 100, got ${per_page}"
    fi
}

test_t16_unauthenticated_access() {
    log_section "T16: Unauthenticated access"

    local response
    response=$(api_request_no_auth GET "/api/v1/notifications")

    assert_status "$response" "401" "T16: 401 without auth" || true
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "============================================="
    echo "  OpenCTEM Notification API Test Suite"
    echo "============================================="
    echo "  Target: ${BASE_URL}"
    echo "============================================="

    preflight
    login

    test_t01_list_notifications
    test_t02_unread_count
    test_t03_get_default_preferences
    test_t04_update_preferences_valid
    test_t05_update_preferences_invalid_digest
    test_t06_update_preferences_invalid_severity
    test_t07_update_preferences_too_many_muted
    test_t08_update_preferences_partial
    test_t09_reset_preferences
    test_t10_mark_all_as_read
    test_t11_mark_single_invalid_id
    test_t12_mark_single_nonexistent
    test_t13_list_with_filters
    test_t14_list_with_pagination
    test_t15_list_invalid_per_page
    test_t16_unauthenticated_access

    # Summary
    log_section "Summary"
    echo ""
    echo -e "  Total:  ${TOTAL}"
    echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
    echo -e "  ${RED}Failed: ${FAILED}${NC}"
    echo ""

    if [[ "$FAILED" -gt 0 ]]; then
        echo -e "${RED}Some tests failed.${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed.${NC}"
        exit 0
    fi
}

main "$@"
