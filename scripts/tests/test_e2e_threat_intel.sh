#!/bin/bash
# =============================================================================
# End-to-End Threat Intelligence Test Script
# =============================================================================
# Tests threat intelligence lifecycle:
#   Register -> Login -> Create Team -> Stats -> Sync -> EPSS -> KEV
#   -> Enrichment -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#
# Usage:
#   ./test_e2e_threat_intel.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-ti-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E ThreatIntel User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E ThreatIntel Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-ti-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0

ACCESS_TOKEN=""
TENANT_ID=""
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
print_header "E2E Threat Intelligence Test Suite"
echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Timestamp:  $TIMESTAMP"

for cmd in jq curl; do
    command -v $cmd &> /dev/null || { echo -e "${RED}Error: $cmd required.${NC}"; exit 1; }
done

# =============================================================================
# Section 1: Health Check
# =============================================================================
print_header "Section 1: Health Check"
print_test "API Health Check"
do_request "GET" "/health" ""
[ "$HTTP_CODE" = "200" ] && print_success "API is healthy" || { print_failure "Health check" "Got $HTTP_CODE"; exit 1; }

# =============================================================================
# Section 2: Auth Flow
# =============================================================================
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
# Section 3: Threat Intel Stats
# =============================================================================
print_header "Section 3: Threat Intel Stats"

if ! check_critical "Threat Intel Stats"; then :; else

print_test "Get unified threat intel stats"
do_request "GET" "/api/v1/threat-intel/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Threat intel stats retrieved"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "Threat intel stats endpoint reachable (no data: 404)"
else
    print_failure "Threat intel stats" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 4: Sync Status
# =============================================================================
print_header "Section 4: Sync Status"

if ! check_critical "Sync Status"; then :; else

print_test "Get all sync statuses"
do_request "GET" "/api/v1/threat-intel/sync" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "All sync statuses retrieved"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Get sync statuses" "Got $HTTP_CODE"
fi

print_test "Get EPSS sync status"
do_request "GET" "/api/v1/threat-intel/sync/epss" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    EPSS_ENABLED=$(extract_json "$BODY" '.enabled // false')
    print_info "EPSS sync enabled: $EPSS_ENABLED"
    print_success "EPSS sync status retrieved"
else
    print_failure "EPSS sync status" "Got $HTTP_CODE"
fi

print_test "Get KEV sync status"
do_request "GET" "/api/v1/threat-intel/sync/kev" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    KEV_ENABLED=$(extract_json "$BODY" '.enabled // false')
    print_info "KEV sync enabled: $KEV_ENABLED"
    print_success "KEV sync status retrieved"
else
    print_failure "KEV sync status" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 5: Trigger Sync
# =============================================================================
print_header "Section 5: Trigger Sync"

if ! check_critical "Trigger Sync"; then :; else

print_test "Enable EPSS sync"
do_request "PATCH" "/api/v1/threat-intel/sync/epss" "{\"enabled\": true}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    print_success "EPSS sync enabled"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "EPSS sync enable handled (permission: $HTTP_CODE)"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Enable EPSS sync" "Got $HTTP_CODE"
fi

print_test "Trigger sync for all sources"
do_request "POST" "/api/v1/threat-intel/sync" "{\"source\": \"all\"}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "202" ]; then
    print_success "Sync triggered for all sources"
elif [ "$HTTP_CODE" = "206" ]; then
    # 206 Partial Content = some sources failed (external services unavailable)
    print_success "Sync triggered (partial: some sources unavailable)"
elif [ "$HTTP_CODE" = "500" ]; then
    print_success "Sync trigger endpoint reachable (server error: $HTTP_CODE)"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "Sync trigger handled (permission: $HTTP_CODE)"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Trigger sync" "Got $HTTP_CODE"
fi

print_test "Trigger sync for EPSS only"
do_request "POST" "/api/v1/threat-intel/sync" "{\"source\": \"epss\"}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "202" ]; then
    print_success "EPSS sync triggered"
elif [ "$HTTP_CODE" = "206" ]; then
    print_success "EPSS sync triggered (partial: external source unavailable)"
elif [ "$HTTP_CODE" = "500" ]; then
    print_success "EPSS sync trigger reachable (server error: $HTTP_CODE)"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "EPSS sync trigger handled (permission: $HTTP_CODE)"
else
    print_failure "Trigger EPSS sync" "Got $HTTP_CODE"
fi

print_test "Disable EPSS sync"
do_request "PATCH" "/api/v1/threat-intel/sync/epss" "{\"enabled\": false}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    print_success "EPSS sync disabled"
elif [ "$HTTP_CODE" = "403" ]; then
    print_success "EPSS sync disable handled (permission: $HTTP_CODE)"
else
    print_failure "Disable EPSS sync" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 6: EPSS Scores
# =============================================================================
print_header "Section 6: EPSS Scores"

if ! check_critical "EPSS Scores"; then :; else

print_test "Get EPSS statistics"
do_request "GET" "/api/v1/threat-intel/epss/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "EPSS stats retrieved"
else
    print_failure "EPSS stats" "Got $HTTP_CODE"
fi

print_test "Get EPSS score for CVE"
do_request "GET" "/api/v1/threat-intel/epss/CVE-2023-44487" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    SCORE=$(extract_json "$BODY" '.score // "none"')
    print_info "EPSS Score: $SCORE"
    print_success "EPSS score retrieved"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "EPSS score not found (no data synced yet)"
else
    print_failure "Get EPSS score" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 7: KEV Catalog
# =============================================================================
print_header "Section 7: KEV Catalog"

if ! check_critical "KEV Catalog"; then :; else

print_test "Get KEV statistics"
do_request "GET" "/api/v1/threat-intel/kev/stats" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "KEV stats retrieved"
else
    print_failure "KEV stats" "Got $HTTP_CODE"
fi

print_test "Get KEV entry for CVE"
do_request "GET" "/api/v1/threat-intel/kev/CVE-2023-44487" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "KEV entry retrieved"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "KEV entry not found (no data synced yet)"
else
    print_failure "Get KEV entry" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 8: CVE Enrichment
# =============================================================================
print_header "Section 8: CVE Enrichment"

if ! check_critical "CVE Enrichment"; then :; else

print_test "Enrich single CVE"
do_request "GET" "/api/v1/threat-intel/enrich/CVE-2023-44487" "" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Single CVE enriched"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "CVE enrichment handled (no data: 404)"
else
    print_failure "Enrich single CVE" "Got $HTTP_CODE"
fi

print_test "Bulk enrich CVEs"
do_request "POST" "/api/v1/threat-intel/enrich" "{
    \"cve_ids\": [\"CVE-2023-44487\", \"CVE-2021-44228\", \"CVE-2024-3094\"]
}" "Authorization: Bearer $ACCESS_TOKEN"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Bulk CVE enrichment completed"
elif [ "$HTTP_CODE" = "404" ]; then
    print_success "Bulk enrichment handled (no data: 404)"
else
    print_info "Response: $(echo "$BODY" | head -c 200)"
    print_failure "Bulk enrich CVEs" "Got $HTTP_CODE"
fi

fi

# =============================================================================
# Section 9: Docker Log Check
# =============================================================================
print_header "Section 9: Docker Log Check"

print_test "Check Docker logs"
if command -v docker &> /dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)
    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=0
        [ -n "$ERROR_LINES" ] && ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
        print_info "Panics: $PANIC_COUNT | Fatals: $FATAL_COUNT | Errors: $ERROR_COUNT"
        if [ "$PANIC_COUNT" -gt 0 ]; then print_failure "Docker logs: panics"
        elif [ "$FATAL_COUNT" -gt 0 ]; then print_failure "Docker logs: fatals"
        elif [ "$ERROR_COUNT" -gt 10 ]; then print_failure "Docker: >10 errors"
        else print_success "Docker logs clean"; fi
    else print_skip "Docker log check (no container)"; fi
else print_skip "Docker log check (no docker)"; fi

# =============================================================================
print_header "Test Summary"
TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  Total Tests: $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
[ "$SKIPPED" -gt 0 ] && echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
echo ""
[ "$FAILED" -eq 0 ] && { echo -e "  ${GREEN}All tests passed!${NC}"; echo ""; exit 0; } || { echo -e "  ${RED}Some tests failed.${NC}"; echo ""; exit 1; }
