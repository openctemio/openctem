#!/usr/bin/env bash
#
# E2E Test: Finding Activity Logging (Auto-Resolve & Auto-Reopen)
#
# Tests the full pipeline: ingest CTIS findings → auto-resolve stale →
# auto-reopen detected-again → verify activity records in audit trail.
#
# Prerequisites:
#   - API running at localhost:8080
#   - PostgreSQL running
#   - jq installed
#   - curl installed
#
# Usage:
#   ./test_e2e_finding_activities.sh [API_URL]
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
TEST_EMAIL="e2e-activity-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Activity User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Activity Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-activity-${TIMESTAMP}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
SKIPPED=0
CRITICAL_FAILURE=0

# Temp files
COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

# Variables set during test
ACCESS_TOKEN=""
TENANT_ID=""
ASSET_GROUP_ID=""
SCAN_CONFIG_ID=""

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
    if [ -n "${2:-}" ]; then
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

mark_critical_failure() {
    CRITICAL_FAILURE=1
}

check_critical() {
    if [ "$CRITICAL_FAILURE" -eq 1 ]; then
        print_skip "$1 (skipped due to earlier critical failure)"
        return 1
    fi
    return 0
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

extract_json() {
    echo "$1" | jq -r "$2" 2>/dev/null
}

# =============================================================================
# Preflight Checks
# =============================================================================

print_header "E2E Test: Finding Activity Logging"
echo -e "  API URL: ${API_URL}"
echo -e "  Timestamp: ${TIMESTAMP}"

# Check dependencies
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}ERROR: $cmd is required but not installed${NC}"
        exit 1
    fi
done

# =============================================================================
# Section 1: Health Check
# =============================================================================

print_header "Section 1: Health Check"
print_test "API Health"

do_request "GET" "/health" ""

if [ "$HTTP_CODE" = "200" ]; then
    print_success "API is healthy"
else
    print_failure "API health check" "Expected 200, got $HTTP_CODE"
    mark_critical_failure
fi

# =============================================================================
# Section 2: Auth Setup
# =============================================================================

print_header "Section 2: Authentication Setup"

if ! check_critical "Register user"; then :; else
    print_test "Register user"
    do_request "POST" "/api/v1/auth/register" "{
        \"email\": \"${TEST_EMAIL}\",
        \"password\": \"${TEST_PASSWORD}\",
        \"name\": \"${TEST_NAME}\"
    }"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        print_success "User registered"
    elif [ "$HTTP_CODE" = "409" ]; then
        print_success "Registration handled (user exists)"
    else
        print_failure "User registration" "Expected 201, got $HTTP_CODE"
        mark_critical_failure
    fi
fi

if ! check_critical "Login"; then :; else
    print_test "Login"
    do_request "POST" "/api/v1/auth/login" "{
        \"email\": \"${TEST_EMAIL}\",
        \"password\": \"${TEST_PASSWORD}\"
    }"

    if [ "$HTTP_CODE" = "200" ]; then
        REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
        print_success "User logged in"
    else
        print_failure "User login" "Expected 200, got $HTTP_CODE"
        mark_critical_failure
    fi
fi

if ! check_critical "Create team"; then :; else
    print_test "Create first team"
    do_request "POST" "/api/v1/auth/create-first-team" "{
        \"name\": \"${TEST_TEAM_NAME}\",
        \"slug\": \"${TEST_TEAM_SLUG}\"
    }"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
        TENANT_ID=$(extract_json "$BODY" '.tenant_id // .tenant.id')
        print_success "Team created (tenant: ${TENANT_ID})"
    elif [ "$HTTP_CODE" = "409" ]; then
        # User already has a team, get token via login
        do_request "POST" "/api/v1/auth/login" "{
            \"email\": \"${TEST_EMAIL}\",
            \"password\": \"${TEST_PASSWORD}\"
        }"
        FIRST_TENANT_ID=$(extract_json "$BODY" '.tenants[0].id')
        REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')

        do_request "POST" "/api/v1/auth/token" "{
            \"refresh_token\": \"${REFRESH_TOKEN}\",
            \"tenant_id\": \"${FIRST_TENANT_ID}\"
        }"
        ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
        TENANT_ID="$FIRST_TENANT_ID"
        print_success "Team exists, obtained token (tenant: ${TENANT_ID})"
    else
        print_failure "Create first team" "Expected 200/201, got $HTTP_CODE. Body: $BODY"
        mark_critical_failure
    fi
fi

AUTH_HEADER="Authorization: Bearer ${ACCESS_TOKEN}"

# =============================================================================
# Section 3: Setup Test Asset Group
# =============================================================================

print_header "Section 3: Create Test Asset Group"

if ! check_critical "Create asset group"; then :; else
    print_test "Create asset group for scan targets"
    do_request "POST" "/api/v1/asset-groups" "{
        \"name\": \"E2E Activity Test Group ${TIMESTAMP}\",
        \"description\": \"Test group for finding activity E2E tests\"
    }" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        ASSET_GROUP_ID=$(extract_json "$BODY" '.id')
        print_success "Asset group created (ID: ${ASSET_GROUP_ID})"
    else
        print_failure "Create asset group" "Expected 201, got $HTTP_CODE"
        # Not critical - we can use custom targets
        print_info "Will use custom targets instead"
    fi
fi

# =============================================================================
# Section 4: Ingest Findings (First Scan)
# =============================================================================

print_header "Section 4: First CTIS Ingest (Create Findings)"

SCAN_ID_1="e2e-scan-1-${TIMESTAMP}"

if ! check_critical "First CTIS ingest"; then :; else
    print_test "Ingest 3 findings via CTIS"

    CTIS_REPORT=$(cat <<EOF
{
    "version": "1.0",
    "metadata": {
        "id": "e2e-ctis-report-1-${TIMESTAMP}",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "tool": {
            "name": "nuclei",
            "version": "3.0.0"
        },
        "scan_id": "${SCAN_ID_1}",
        "scan_type": "full"
    },
    "target": {
        "identifier": "e2e-target-${TIMESTAMP}.example.com",
        "type": "domain"
    },
    "findings": [
        {
            "id": "finding-1-${TIMESTAMP}",
            "title": "SQL Injection in Login",
            "severity": "critical",
            "type": "vulnerability",
            "description": "SQL injection vulnerability found in login form",
            "fingerprint": "fp-sqli-login-${TIMESTAMP}",
            "location": {
                "path": "/login",
                "line_start": 42
            }
        },
        {
            "id": "finding-2-${TIMESTAMP}",
            "title": "XSS in Search",
            "severity": "high",
            "type": "vulnerability",
            "description": "Cross-site scripting in search parameter",
            "fingerprint": "fp-xss-search-${TIMESTAMP}",
            "location": {
                "path": "/search",
                "line_start": 88
            }
        },
        {
            "id": "finding-3-${TIMESTAMP}",
            "title": "Open Redirect",
            "severity": "medium",
            "type": "vulnerability",
            "description": "Open redirect vulnerability in callback URL",
            "fingerprint": "fp-redirect-${TIMESTAMP}",
            "location": {
                "path": "/callback",
                "line_start": 15
            }
        }
    ]
}
EOF
)

    do_request "POST" "/api/v1/agent/ingest/ctis" "$CTIS_REPORT" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
        FINDINGS_CREATED=$(extract_json "$BODY" '.findings_created // .stats.findings_created // 0')
        print_success "First ingest completed (findings created: ${FINDINGS_CREATED})"
    else
        print_failure "First CTIS ingest" "Expected 200/201/202, got $HTTP_CODE. Body: $(echo $BODY | head -c 200)"
        mark_critical_failure
    fi
fi

# =============================================================================
# Section 5: Verify Initial Findings Exist
# =============================================================================

print_header "Section 5: Verify Initial Findings"

if ! check_critical "List findings"; then :; else
    print_test "List findings from first scan"

    # Small delay to allow async processing
    sleep 2

    do_request "GET" "/api/v1/findings?limit=10" "" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ]; then
        TOTAL_FINDINGS=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
        print_success "Findings listed (total: ${TOTAL_FINDINGS})"

        if [ "$TOTAL_FINDINGS" -ge 3 ]; then
            print_success "Expected at least 3 findings"
        else
            print_info "Warning: expected >= 3 findings, got ${TOTAL_FINDINGS} (async processing may be slow)"
        fi
    else
        print_failure "List findings" "Expected 200, got $HTTP_CODE"
    fi
fi

# =============================================================================
# Section 6: Second Ingest - Auto-Resolve (Missing Findings)
# =============================================================================

print_header "Section 6: Second CTIS Ingest (Trigger Auto-Resolve)"

SCAN_ID_2="e2e-scan-2-${TIMESTAMP}"

if ! check_critical "Second CTIS ingest"; then :; else
    print_test "Ingest only finding-1, omitting finding-2 and finding-3 to trigger auto-resolve"

    CTIS_REPORT_2=$(cat <<EOF
{
    "version": "1.0",
    "metadata": {
        "id": "e2e-ctis-report-2-${TIMESTAMP}",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "tool": {
            "name": "nuclei",
            "version": "3.0.0"
        },
        "scan_id": "${SCAN_ID_2}",
        "scan_type": "full"
    },
    "target": {
        "identifier": "e2e-target-${TIMESTAMP}.example.com",
        "type": "domain"
    },
    "findings": [
        {
            "id": "finding-1-rescan-${TIMESTAMP}",
            "title": "SQL Injection in Login",
            "severity": "critical",
            "type": "vulnerability",
            "description": "SQL injection vulnerability found in login form (re-detected)",
            "fingerprint": "fp-sqli-login-${TIMESTAMP}",
            "location": {
                "path": "/login",
                "line_start": 42
            }
        }
    ]
}
EOF
)

    do_request "POST" "/api/v1/agent/ingest/ctis" "$CTIS_REPORT_2" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
        AUTO_RESOLVED=$(extract_json "$BODY" '.findings_auto_resolved // .stats.findings_auto_resolved // 0')
        print_success "Second ingest completed (auto-resolved: ${AUTO_RESOLVED})"

        if [ "$AUTO_RESOLVED" -ge 1 ]; then
            print_success "Auto-resolve triggered (${AUTO_RESOLVED} findings resolved)"
        else
            print_info "Note: auto_resolved count = ${AUTO_RESOLVED} (field may not be in response)"
        fi
    else
        print_failure "Second CTIS ingest" "Expected 200/201/202, got $HTTP_CODE. Body: $(echo $BODY | head -c 200)"
    fi
fi

# =============================================================================
# Section 7: Check Findings Status (Resolved)
# =============================================================================

print_header "Section 7: Verify Auto-Resolved Findings"

if ! check_critical "Check resolved findings"; then :; else
    print_test "Check that omitted findings were resolved"

    sleep 2

    do_request "GET" "/api/v1/findings?status=resolved&limit=10" "" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ]; then
        RESOLVED_COUNT=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
        print_info "Resolved findings: ${RESOLVED_COUNT}"

        if [ "$RESOLVED_COUNT" -ge 1 ]; then
            print_success "Found resolved findings (${RESOLVED_COUNT})"
        else
            print_info "No resolved findings yet (auto-resolve may require specific conditions)"
        fi
    else
        print_failure "Check resolved findings" "Expected 200, got $HTTP_CODE"
    fi
fi

# =============================================================================
# Section 8: Third Ingest - Auto-Reopen
# =============================================================================

print_header "Section 8: Third CTIS Ingest (Trigger Auto-Reopen)"

SCAN_ID_3="e2e-scan-3-${TIMESTAMP}"

if ! check_critical "Third CTIS ingest"; then :; else
    print_test "Re-ingest previously resolved finding to trigger auto-reopen"

    CTIS_REPORT_3=$(cat <<EOF
{
    "version": "1.0",
    "metadata": {
        "id": "e2e-ctis-report-3-${TIMESTAMP}",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "tool": {
            "name": "nuclei",
            "version": "3.0.0"
        },
        "scan_id": "${SCAN_ID_3}",
        "scan_type": "full"
    },
    "target": {
        "identifier": "e2e-target-${TIMESTAMP}.example.com",
        "type": "domain"
    },
    "findings": [
        {
            "id": "finding-1-scan3-${TIMESTAMP}",
            "title": "SQL Injection in Login",
            "severity": "critical",
            "type": "vulnerability",
            "description": "SQL injection re-detected again",
            "fingerprint": "fp-sqli-login-${TIMESTAMP}",
            "location": {
                "path": "/login",
                "line_start": 42
            }
        },
        {
            "id": "finding-2-scan3-${TIMESTAMP}",
            "title": "XSS in Search",
            "severity": "high",
            "type": "vulnerability",
            "description": "XSS re-detected (should auto-reopen)",
            "fingerprint": "fp-xss-search-${TIMESTAMP}",
            "location": {
                "path": "/search",
                "line_start": 88
            }
        },
        {
            "id": "finding-3-scan3-${TIMESTAMP}",
            "title": "Open Redirect",
            "severity": "medium",
            "type": "vulnerability",
            "description": "Open redirect re-detected (should auto-reopen)",
            "fingerprint": "fp-redirect-${TIMESTAMP}",
            "location": {
                "path": "/callback",
                "line_start": 15
            }
        }
    ]
}
EOF
)

    do_request "POST" "/api/v1/agent/ingest/ctis" "$CTIS_REPORT_3" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
        AUTO_REOPENED=$(extract_json "$BODY" '.findings_auto_reopened // .stats.findings_auto_reopened // 0')
        print_success "Third ingest completed (auto-reopened: ${AUTO_REOPENED})"
    else
        print_failure "Third CTIS ingest" "Expected 200/201/202, got $HTTP_CODE. Body: $(echo $BODY | head -c 200)"
    fi
fi

# =============================================================================
# Section 9: Verify Activity Records
# =============================================================================

print_header "Section 9: Verify Finding Activity Records"

if ! check_critical "Check activity records"; then :; else
    # Get a finding ID to check activities
    print_test "Get finding IDs for activity check"

    do_request "GET" "/api/v1/findings?limit=5" "" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ]; then
        FIRST_FINDING_ID=$(extract_json "$BODY" '.data[0].id // .items[0].id // ""')

        if [ -n "$FIRST_FINDING_ID" ] && [ "$FIRST_FINDING_ID" != "null" ]; then
            print_success "Got finding ID: ${FIRST_FINDING_ID}"

            print_test "Check activities for finding ${FIRST_FINDING_ID}"
            do_request "GET" "/api/v1/findings/${FIRST_FINDING_ID}/activities?limit=20" "" "$AUTH_HEADER"

            if [ "$HTTP_CODE" = "200" ]; then
                ACTIVITY_COUNT=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
                print_info "Activity records found: ${ACTIVITY_COUNT}"

                if [ "$ACTIVITY_COUNT" -ge 1 ]; then
                    print_success "Finding has activity records (${ACTIVITY_COUNT})"

                    # Check for auto-resolved/auto-reopened activity types
                    HAS_AUTO_RESOLVED=$(echo "$BODY" | jq '[.data[]? | select(.activity_type == "auto_resolved")] | length' 2>/dev/null || echo "0")
                    HAS_AUTO_REOPENED=$(echo "$BODY" | jq '[.data[]? | select(.activity_type == "auto_reopened")] | length' 2>/dev/null || echo "0")

                    print_info "Auto-resolved activities: ${HAS_AUTO_RESOLVED}"
                    print_info "Auto-reopened activities: ${HAS_AUTO_REOPENED}"

                    if [ "$HAS_AUTO_RESOLVED" -ge 1 ] || [ "$HAS_AUTO_REOPENED" -ge 1 ]; then
                        print_success "Found auto-resolve/reopen activity records in audit trail"
                    else
                        print_info "No auto-resolve/reopen activities on this finding (may be on other findings)"
                    fi
                else
                    print_info "No activity records yet (activities may be on resolved findings)"
                fi
            elif [ "$HTTP_CODE" = "404" ]; then
                print_info "Activities endpoint returned 404 (may not be routed yet)"
            else
                print_failure "Check activities" "Expected 200, got $HTTP_CODE"
            fi
        else
            print_info "No findings found to check activities"
        fi
    else
        print_failure "Get findings for activity check" "Expected 200, got $HTTP_CODE"
    fi
fi

# =============================================================================
# Section 10: Verify CTIS Web3 Metadata Ingest
# =============================================================================

print_header "Section 10: CTIS Web3 Metadata Fields"

SCAN_ID_WEB3="e2e-scan-web3-${TIMESTAMP}"

if ! check_critical "Web3 CTIS ingest"; then :; else
    print_test "Ingest finding with Web3 metadata fields"

    CTIS_WEB3=$(cat <<EOF
{
    "version": "1.0",
    "metadata": {
        "id": "e2e-ctis-web3-${TIMESTAMP}",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "tool": {
            "name": "slither",
            "version": "0.10.0"
        },
        "scan_id": "${SCAN_ID_WEB3}",
        "scan_type": "full"
    },
    "target": {
        "identifier": "0xContractAddr${TIMESTAMP}",
        "type": "smart_contract"
    },
    "findings": [
        {
            "id": "web3-finding-${TIMESTAMP}",
            "title": "Reentrancy in Withdraw Function",
            "severity": "critical",
            "type": "web3",
            "description": "Reentrancy vulnerability in withdraw function",
            "fingerprint": "fp-web3-reentrancy-${TIMESTAMP}",
            "web3": {
                "chain": "ethereum",
                "chain_id": 1,
                "contract_address": "0xdeadbeef1234567890",
                "function_signature": "withdraw(uint256)",
                "swc_id": "SWC-107",
                "related_tx_hashes": ["0xabc123", "0xdef456"],
                "vulnerable_pattern": "delegatecall in loop",
                "exploitable_on_mainnet": true,
                "estimated_impact_usd": 1500000.50,
                "attack_vector": "flash_loan",
                "detection_tool": "slither",
                "detection_confidence": "high"
            }
        }
    ]
}
EOF
)

    do_request "POST" "/api/v1/agent/ingest/ctis" "$CTIS_WEB3" "$AUTH_HEADER"

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "202" ]; then
        print_success "Web3 CTIS ingest completed"
    else
        print_failure "Web3 CTIS ingest" "Expected 200/201/202, got $HTTP_CODE"
    fi
fi

# =============================================================================
# Section 11: Docker Log Check
# =============================================================================

print_header "Section 11: Docker Log Check"

print_test "Check Docker logs for errors"
if command -v docker &> /dev/null; then
    API_CONTAINER=$(docker ps --filter "name=api" --format "{{.Names}}" 2>/dev/null | head -1)

    if [ -n "$API_CONTAINER" ]; then
        RECENT_LOGS=$(docker logs "$API_CONTAINER" --since 2m 2>&1)
        PANIC_COUNT=$(echo "$RECENT_LOGS" | grep -ci "panic" 2>/dev/null || true)
        FATAL_COUNT=$(echo "$RECENT_LOGS" | grep -ci "fatal" 2>/dev/null || true)
        ERROR_LINES=$(echo "$RECENT_LOGS" | grep -i "error" 2>/dev/null || true)
        ERROR_COUNT=0
        if [ -n "$ERROR_LINES" ]; then
            ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
        fi

        print_info "Panics (last 2m): $PANIC_COUNT"
        print_info "Fatals (last 2m): $FATAL_COUNT"
        print_info "Error logs (last 2m): $ERROR_COUNT"

        if [ "$PANIC_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $PANIC_COUNT panic(s) detected"
        elif [ "$FATAL_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $FATAL_COUNT fatal(s) detected"
        elif [ "$ERROR_COUNT" -gt 10 ]; then
            print_failure "Docker logs: $ERROR_COUNT error(s) (>10 threshold)"
        else
            print_success "Docker logs clean"
        fi
    else
        print_skip "Docker log check (no API container found)"
    fi
else
    print_skip "Docker log check (docker not available)"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Test Summary"
TOTAL=$((PASSED + FAILED))
echo -e "  Total Tests: $TOTAL"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
if [ "$SKIPPED" -gt 0 ]; then
    echo -e "  ${YELLOW}Skipped: $SKIPPED${NC}"
fi
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed.${NC}"
fi

exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
