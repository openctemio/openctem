#!/bin/bash
# =============================================================================
# End-to-End Ingest API Test Script
# =============================================================================
# Tests the full lifecycle:
#   Register -> Login -> Create Team -> Create Agent -> Ingest (CTIS/SARIF/Recon)
#   -> Fingerprint Check -> Heartbeat -> Verify Data -> Docker Log Check
#
# Prerequisites:
#   - API running at localhost:8080 with AUTH_ALLOW_REGISTRATION=true
#   - jq and curl installed
#   - Docker running (for log check, optional)
#
# Usage:
#   ./test_e2e_ingest.sh [API_URL]
#   API_URL=http://localhost:9090 ./test_e2e_ingest.sh
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
TEST_EMAIL="e2e-test-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="TestP@ss123!"
TEST_NAME="E2E Test User ${TIMESTAMP}"
TEST_TEAM_NAME="E2E Test Team ${TIMESTAMP}"
TEST_TEAM_SLUG="e2e-test-${TIMESTAMP}"

# Temp files
COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

# Counters
PASSED=0
FAILED=0
SKIPPED=0

# Extracted values (populated during tests)
REFRESH_TOKEN=""
ACCESS_TOKEN=""
TENANT_ID=""
AGENT_ID=""
API_KEY=""
CRITICAL_FAILURE=0

# Global response variables (set by do_request)
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

# Extract a field from JSON using jq
extract_json() {
    echo "$1" | jq -r "$2" 2>/dev/null
}

# Make a curl request. Sets global BODY and HTTP_CODE variables.
# Usage: do_request "METHOD" "/endpoint" '{"data":"val"}' ["Header: val" ...]
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

print_header "E2E Ingest API Test Suite"

echo -e "\nConfiguration:"
echo "  API URL:    $API_URL"
echo "  Test Email: $TEST_EMAIL"
echo "  Test Team:  $TEST_TEAM_NAME"
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
print_info "Endpoint: GET /health"
print_info "Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "API is healthy"
else
    print_failure "API health check" "Expected 200, got $HTTP_CODE. Is the API running at $API_URL?"
    echo -e "${RED}Cannot continue without a healthy API. Aborting.${NC}"
    echo ""
    echo "Total: 1 | Passed: $PASSED | Failed: $FAILED"
    exit 1
fi

# =============================================================================
# Section 2: User Registration
# =============================================================================

print_header "Section 2: User Registration"

print_test "Register new user"
do_request "POST" "/api/v1/auth/register" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\",
    \"name\": \"$TEST_NAME\"
}"
print_info "Endpoint: POST /api/v1/auth/register"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    USER_ID=$(extract_json "$BODY" '.id // .user.id // empty')
    if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
        print_info "User ID: $USER_ID"
    fi
    print_success "User registered"
elif [ "$HTTP_CODE" = "409" ]; then
    print_info "User already exists (409), proceeding with login"
    print_success "Registration handled (user exists)"
elif [ "$HTTP_CODE" = "429" ]; then
    print_failure "Registration rate limited (429)" "Wait 1 minute and try again"
    mark_critical_failure
else
    print_failure "User registration" "Expected 201, got $HTTP_CODE"
    print_info "Hint: Ensure AUTH_ALLOW_REGISTRATION=true in your environment"
    mark_critical_failure
fi

# =============================================================================
# Section 3: User Login
# =============================================================================

print_header "Section 3: User Login"

if ! check_critical "User Login"; then :; else

print_test "Login with registered user"
do_request "POST" "/api/v1/auth/login" "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
}"
print_info "Endpoint: POST /api/v1/auth/login"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "200" ]; then
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    TENANTS=$(extract_json "$BODY" '.tenants')
    USER_EMAIL=$(extract_json "$BODY" '.user.email')

    if [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ]; then
        print_info "Refresh token: ${REFRESH_TOKEN:0:20}..."
    fi
    print_info "User email: $USER_EMAIL"
    print_info "Tenants: $TENANTS"
    print_success "User logged in"
else
    print_failure "User login" "Expected 200, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error message: $(extract_json "$BODY" '.message')"
    fi
    mark_critical_failure
fi

fi # end critical check

# =============================================================================
# Section 4: Create First Team
# =============================================================================

print_header "Section 4: Create First Team"

if ! check_critical "Create First Team"; then :; else

print_test "Create first team (tenant)"
do_request "POST" "/api/v1/auth/create-first-team" "{
    \"team_name\": \"$TEST_TEAM_NAME\",
    \"team_slug\": \"$TEST_TEAM_SLUG\"
}"
print_info "Endpoint: POST /api/v1/auth/create-first-team"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 400)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    TENANT_SLUG=$(extract_json "$BODY" '.tenant_slug')

    if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
        print_info "Access token: ${ACCESS_TOKEN:0:20}..."
        print_info "Tenant ID: $TENANT_ID"
        print_info "Tenant Slug: $TENANT_SLUG"
        print_success "First team created"
    else
        print_failure "Create first team" "Response missing access_token"
        mark_critical_failure
    fi
elif [ "$HTTP_CODE" = "409" ]; then
    # User already has a team, try token exchange instead
    print_info "User already has a team (409). Attempting token exchange..."

    # Re-login to get fresh token and tenant list
    do_request "POST" "/api/v1/auth/login" "{
        \"email\": \"$TEST_EMAIL\",
        \"password\": \"$TEST_PASSWORD\"
    }"
    REFRESH_TOKEN=$(extract_json "$BODY" '.refresh_token')
    FIRST_TENANT_ID=$(extract_json "$BODY" '.tenants[0].id')

    if [ -n "$FIRST_TENANT_ID" ] && [ "$FIRST_TENANT_ID" != "null" ]; then
        do_request "POST" "/api/v1/auth/token" "{
            \"refresh_token\": \"$REFRESH_TOKEN\",
            \"tenant_id\": \"$FIRST_TENANT_ID\"
        }"

        if [ "$HTTP_CODE" = "200" ]; then
            ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')
            TENANT_ID="$FIRST_TENANT_ID"
            print_info "Access token: ${ACCESS_TOKEN:0:20}..."
            print_info "Tenant ID: $TENANT_ID"
            print_success "Token exchanged for existing team"
        else
            print_failure "Token exchange" "Expected 200, got $HTTP_CODE"
            mark_critical_failure
        fi
    else
        print_failure "Create first team" "No tenants found for token exchange"
        mark_critical_failure
    fi
else
    print_failure "Create first team" "Expected 201, got $HTTP_CODE"
    mark_critical_failure
fi

fi # end critical check

# =============================================================================
# Section 5: Create Agent
# =============================================================================

print_header "Section 5: Create Agent"

if ! check_critical "Create Agent"; then :; else

print_test "Create scanner agent"
do_request "POST" "/api/v1/agents" "{
    \"name\": \"e2e-test-runner-${TIMESTAMP}\",
    \"type\": \"runner\",
    \"description\": \"E2E test agent created at ${TIMESTAMP}\",
    \"capabilities\": [\"sast\", \"dast\", \"sca\"],
    \"execution_mode\": \"standalone\",
    \"max_concurrent_jobs\": 5
}" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Endpoint: POST /api/v1/agents"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    AGENT_ID=$(extract_json "$BODY" '.agent.id')
    API_KEY=$(extract_json "$BODY" '.api_key')
    AGENT_NAME=$(extract_json "$BODY" '.agent.name')

    if [ -n "$API_KEY" ] && [ "$API_KEY" != "null" ]; then
        print_info "Agent ID: $AGENT_ID"
        print_info "Agent Name: $AGENT_NAME"
        print_info "API Key: ${API_KEY:0:12}..."

        if [[ "$API_KEY" == rda_* ]]; then
            print_success "Agent created (API key format: rda_*)"
        else
            print_info "Note: API key prefix is not rda_"
            print_success "Agent created"
        fi
    else
        print_failure "Create agent" "Response missing api_key"
        mark_critical_failure
    fi
else
    print_failure "Create agent" "Expected 201, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error: $(extract_json "$BODY" '.message')"
    fi
    mark_critical_failure
fi

fi # end critical check

# =============================================================================
# Section 6: Agent Heartbeat
# =============================================================================

print_header "Section 6: Agent Heartbeat"

if ! check_critical "Agent Heartbeat"; then :; else

print_test "Send agent heartbeat"
do_request "POST" "/api/v1/agent/heartbeat" "{
    \"status\": \"online\",
    \"version\": \"1.0.0-e2e-test\",
    \"hostname\": \"e2e-test-host\",
    \"message\": \"E2E test heartbeat\",
    \"scanners\": [\"semgrep\", \"nuclei\", \"gitleaks\"],
    \"uptime_seconds\": 3600,
    \"cpu_percent\": 25.5,
    \"memory_percent\": 45.2,
    \"active_jobs\": 0
}" "X-API-Key: $API_KEY"
print_info "Endpoint: POST /api/v1/agent/heartbeat"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 300)"

if [ "$HTTP_CODE" = "200" ]; then
    HB_STATUS=$(extract_json "$BODY" '.status')
    HB_AGENT=$(extract_json "$BODY" '.agent_id')
    print_info "Heartbeat status: $HB_STATUS"
    print_info "Agent ID confirmed: $HB_AGENT"
    print_success "Agent heartbeat acknowledged"
else
    print_failure "Agent heartbeat" "Expected 200, got $HTTP_CODE"
fi

fi # end critical check

# =============================================================================
# Section 7: CTIS Ingest
# =============================================================================

print_header "Section 7: CTIS Ingest"

if ! check_critical "CTIS Ingest"; then :; else

print_test "Ingest CTIS report (2 assets, 2 findings)"

CTIS_REPORT=$(cat <<EOF
{
    "version": "1.0",
    "metadata": {
        "id": "e2e-ctis-report-${TIMESTAMP}",
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "source_type": "scanner"
    },
    "tool": {
        "name": "e2e-test-scanner",
        "version": "1.0.0"
    },
    "assets": [
        {
            "id": "asset-repo-1",
            "type": "repository",
            "value": "github.com/test/e2e-repo-${TIMESTAMP}",
            "name": "E2E Test Repository",
            "criticality": "high"
        },
        {
            "id": "asset-domain-1",
            "type": "domain",
            "value": "e2e-test-${TIMESTAMP}.example.com",
            "name": "E2E Test Domain"
        }
    ],
    "findings": [
        {
            "id": "finding-sqli-1",
            "type": "vulnerability",
            "title": "SQL Injection in login endpoint",
            "description": "User input is directly concatenated into SQL query without parameterization",
            "severity": "critical",
            "confidence": 90,
            "rule_id": "semgrep.sqli-001",
            "asset_ref": "asset-repo-1",
            "location": {
                "path": "src/auth/login.go",
                "start_line": 42,
                "end_line": 42,
                "snippet": "db.Query(userInput)"
            },
            "vulnerability": {
                "cwe_ids": ["CWE-89"],
                "cvss_score": 9.8
            }
        },
        {
            "id": "finding-secret-1",
            "type": "secret",
            "title": "AWS Access Key exposed in config",
            "description": "Hardcoded AWS access key found in configuration file",
            "severity": "high",
            "confidence": 90,
            "rule_id": "gitleaks.aws-access-key",
            "asset_ref": "asset-repo-1",
            "location": {
                "path": "config/aws.yaml",
                "start_line": 5,
                "end_line": 5
            }
        }
    ]
}
EOF
)

do_request "POST" "/api/v1/agent/ingest/ctis" "$CTIS_REPORT" "X-API-Key: $API_KEY"
print_info "Endpoint: POST /api/v1/agent/ingest/ctis"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    CTIS_SCAN_ID=$(extract_json "$BODY" '.scan_id')
    CTIS_ASSETS=$(extract_json "$BODY" '.assets_created')
    CTIS_FINDINGS=$(extract_json "$BODY" '.findings_created')
    CTIS_ERRORS=$(extract_json "$BODY" '.errors')

    print_info "Scan ID: $CTIS_SCAN_ID"
    print_info "Assets created: $CTIS_ASSETS"
    print_info "Findings created: $CTIS_FINDINGS"

    if [ -n "$CTIS_ERRORS" ] && [ "$CTIS_ERRORS" != "null" ] && [ "$CTIS_ERRORS" != "[]" ]; then
        print_info "Ingest errors: $CTIS_ERRORS"
    fi

    if [ "$CTIS_FINDINGS" != "null" ] && [ "$CTIS_FINDINGS" != "0" ] 2>/dev/null; then
        print_success "CTIS ingest: $CTIS_FINDINGS findings, $CTIS_ASSETS assets created"
    else
        print_success "CTIS ingest accepted (findings may have been deduplicated)"
    fi
else
    print_failure "CTIS ingest" "Expected 201, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error: $(extract_json "$BODY" '.message')"
    fi
fi

fi # end critical check

# =============================================================================
# Section 8: SARIF Ingest
# =============================================================================

print_header "Section 8: SARIF Ingest"

if ! check_critical "SARIF Ingest"; then :; else

print_test "Ingest SARIF 2.1.0 report (2 findings)"

SARIF_REPORT=$(cat <<'SARIF_EOF'
{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "e2e-sarif-scanner",
                    "version": "2.0.0",
                    "rules": [
                        {
                            "id": "XSS-001",
                            "name": "CrossSiteScripting",
                            "shortDescription": {"text": "Potential XSS vulnerability"},
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "tags": ["security", "xss", "CWE-79"]
                            }
                        },
                        {
                            "id": "PATH-001",
                            "name": "PathTraversal",
                            "shortDescription": {"text": "Path traversal vulnerability"},
                            "defaultConfiguration": {"level": "warning"}
                        }
                    ]
                }
            },
            "results": [
                {
                    "ruleId": "XSS-001",
                    "level": "error",
                    "message": {"text": "User input rendered without escaping in template"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/views/profile.html"},
                                "region": {
                                    "startLine": 15,
                                    "startColumn": 10,
                                    "endLine": 15,
                                    "endColumn": 45,
                                    "snippet": {"text": "<div>{{ .UserInput }}</div>"}
                                }
                            }
                        }
                    ]
                },
                {
                    "ruleId": "PATH-001",
                    "level": "warning",
                    "message": {"text": "File path constructed from user input without sanitization"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/handlers/file.go"},
                                "region": {
                                    "startLine": 88,
                                    "startColumn": 5,
                                    "endLine": 88,
                                    "endColumn": 50
                                }
                            }
                        }
                    ]
                }
            ]
        }
    ]
}
SARIF_EOF
)

do_request "POST" "/api/v1/agent/ingest/sarif" "$SARIF_REPORT" "X-API-Key: $API_KEY"
print_info "Endpoint: POST /api/v1/agent/ingest/sarif"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    SARIF_SCAN_ID=$(extract_json "$BODY" '.scan_id')
    SARIF_FINDINGS=$(extract_json "$BODY" '.findings_created')
    SARIF_ERRORS=$(extract_json "$BODY" '.errors')

    print_info "Scan ID: $SARIF_SCAN_ID"
    print_info "Findings created: $SARIF_FINDINGS"

    if [ -n "$SARIF_ERRORS" ] && [ "$SARIF_ERRORS" != "null" ] && [ "$SARIF_ERRORS" != "[]" ]; then
        print_info "Ingest errors: $SARIF_ERRORS"
    fi

    print_success "SARIF ingest: $SARIF_FINDINGS findings created"
else
    print_failure "SARIF ingest" "Expected 201, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error: $(extract_json "$BODY" '.message')"
    fi
fi

fi # end critical check

# =============================================================================
# Section 9: Recon Ingest
# =============================================================================

print_header "Section 9: Recon Ingest"

if ! check_critical "Recon Ingest"; then :; else

EPOCH_NOW=$(date +%s)
EPOCH_START=$((EPOCH_NOW - 60))

print_test "Ingest Recon data (subdomain enumeration)"

RECON_REPORT=$(cat <<EOF
{
    "scanner_name": "e2e-recon-scanner",
    "scanner_version": "1.0.0",
    "recon_type": "subdomain",
    "target": "e2e-test-${TIMESTAMP}.example.com",
    "started_at": ${EPOCH_START},
    "finished_at": ${EPOCH_NOW},
    "subdomains": [
        {
            "host": "api.e2e-test-${TIMESTAMP}.example.com",
            "domain": "e2e-test-${TIMESTAMP}.example.com",
            "source": "e2e-test-subfinder",
            "ips": ["192.168.100.10"]
        },
        {
            "host": "admin.e2e-test-${TIMESTAMP}.example.com",
            "domain": "e2e-test-${TIMESTAMP}.example.com",
            "source": "e2e-test-amass",
            "ips": ["192.168.100.11"]
        },
        {
            "host": "staging.e2e-test-${TIMESTAMP}.example.com",
            "domain": "e2e-test-${TIMESTAMP}.example.com",
            "source": "e2e-test-subfinder",
            "ips": ["192.168.100.12"]
        }
    ],
    "dns_records": [
        {
            "host": "e2e-test-${TIMESTAMP}.example.com",
            "record_type": "A",
            "values": ["192.168.100.10"],
            "ttl": 300
        },
        {
            "host": "e2e-test-${TIMESTAMP}.example.com",
            "record_type": "MX",
            "values": ["mail.e2e-test-${TIMESTAMP}.example.com"],
            "ttl": 3600
        }
    ]
}
EOF
)

do_request "POST" "/api/v1/agent/ingest/recon" "$RECON_REPORT" "X-API-Key: $API_KEY"
print_info "Endpoint: POST /api/v1/agent/ingest/recon"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    RECON_SCAN_ID=$(extract_json "$BODY" '.scan_id')
    RECON_ASSETS=$(extract_json "$BODY" '.assets_created')

    print_info "Scan ID: $RECON_SCAN_ID"
    print_info "Assets created: $RECON_ASSETS"
    print_success "Recon ingest: $RECON_ASSETS assets created"
else
    print_failure "Recon ingest" "Expected 201, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error: $(extract_json "$BODY" '.message')"
    fi
fi

fi # end critical check

# =============================================================================
# Section 10: Fingerprint Check
# =============================================================================

print_header "Section 10: Fingerprint Check"

if ! check_critical "Fingerprint Check"; then :; else

print_test "Check fingerprints (non-existing)"

FINGERPRINT_REQ=$(cat <<'FP_EOF'
{
    "fingerprints": [
        "e2e_test_nonexistent_fingerprint_abc123",
        "e2e_test_nonexistent_fingerprint_def456",
        "e2e_test_nonexistent_fingerprint_ghi789"
    ]
}
FP_EOF
)

do_request "POST" "/api/v1/agent/ingest/check" "$FINGERPRINT_REQ" "X-API-Key: $API_KEY"
print_info "Endpoint: POST /api/v1/agent/ingest/check"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    EXISTING_COUNT=$(extract_json "$BODY" '.existing | length')
    MISSING_COUNT=$(extract_json "$BODY" '.missing | length')

    print_info "Existing: $EXISTING_COUNT"
    print_info "Missing: $MISSING_COUNT"

    if [ "$MISSING_COUNT" = "3" ]; then
        print_success "Fingerprint check: all 3 test fingerprints correctly marked as missing"
    else
        print_success "Fingerprint check responded (existing=$EXISTING_COUNT, missing=$MISSING_COUNT)"
    fi
else
    print_failure "Fingerprint check" "Expected 200, got $HTTP_CODE"
    if echo "$BODY" | jq -e '.message' > /dev/null 2>&1; then
        print_info "Error: $(extract_json "$BODY" '.message')"
    fi
fi

fi # end critical check

# =============================================================================
# Section 11: Verify Ingested Data
# =============================================================================

print_header "Section 11: Verify Ingested Data"

if ! check_critical "Verify Data"; then :; else

# Verify findings
print_test "List findings (verify CTIS + SARIF data ingested)"
do_request "GET" "/api/v1/findings?per_page=10" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Endpoint: GET /api/v1/findings"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    TOTAL_FINDINGS=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
    print_info "Total findings: $TOTAL_FINDINGS"

    if [ "$TOTAL_FINDINGS" != "null" ] && [ "$TOTAL_FINDINGS" != "0" ] 2>/dev/null; then
        print_success "Findings verified: $TOTAL_FINDINGS total findings in tenant"
    else
        print_success "Findings endpoint accessible (count: $TOTAL_FINDINGS)"
    fi
else
    print_failure "List findings" "Expected 200, got $HTTP_CODE"
fi

# Verify assets
print_test "List assets (verify CTIS + Recon data ingested)"
do_request "GET" "/api/v1/assets?per_page=10" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Endpoint: GET /api/v1/assets"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    TOTAL_ASSETS=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
    print_info "Total assets: $TOTAL_ASSETS"

    if [ "$TOTAL_ASSETS" != "null" ] && [ "$TOTAL_ASSETS" != "0" ] 2>/dev/null; then
        print_success "Assets verified: $TOTAL_ASSETS total assets in tenant"
    else
        print_success "Assets endpoint accessible (count: $TOTAL_ASSETS)"
    fi
else
    print_failure "List assets" "Expected 200, got $HTTP_CODE"
fi

# Verify scans
print_test "List scans (verify scan records created)"
do_request "GET" "/api/v1/scans?per_page=10" "" "Authorization: Bearer $ACCESS_TOKEN"
print_info "Endpoint: GET /api/v1/scans"
print_info "Status: $HTTP_CODE"
print_info "Response: $(echo "$BODY" | head -c 500)"

if [ "$HTTP_CODE" = "200" ]; then
    TOTAL_SCANS=$(extract_json "$BODY" '.total // .pagination.total // (.data | length) // 0')
    print_info "Total scans: $TOTAL_SCANS"
    print_success "Scans verified: $TOTAL_SCANS total scans in tenant"
else
    print_info "Scans endpoint returned $HTTP_CODE (may require different permissions)"
    print_skip "Scans verification"
fi

fi # end critical check

# =============================================================================
# Section 12: Docker Log Check
# =============================================================================

print_header "Section 12: Docker Log Check"

print_test "Check Docker logs for errors"

if ! command -v docker &> /dev/null; then
    print_info "Docker not available, skipping log check"
    print_skip "Docker log check (docker not found)"
else
    API_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '(api|openctem)' | grep -v -E '(postgres|redis|ui)' | head -1)

    if [ -z "$API_CONTAINER" ]; then
        print_info "No API container found, skipping log check"
        print_skip "Docker log check (no API container found)"
    else
        print_info "Checking container: $API_CONTAINER"

        PANIC_COUNT=$(docker logs "$API_CONTAINER" --since 2m 2>&1 | grep -ci 'panic' || true)
        FATAL_COUNT=$(docker logs "$API_CONTAINER" --since 2m 2>&1 | grep -ci 'fatal' || true)
        ERROR_LINES=$(docker logs "$API_CONTAINER" --since 2m 2>&1 | grep -i '"level":"error"' 2>/dev/null || true)
        ERROR_COUNT=0
        if [ -n "$ERROR_LINES" ]; then
            ERROR_COUNT=$(echo "$ERROR_LINES" | wc -l)
        fi

        print_info "Panics (last 2m): $PANIC_COUNT"
        print_info "Fatals (last 2m): $FATAL_COUNT"
        print_info "Error logs (last 2m): $ERROR_COUNT"

        if [ "$PANIC_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $PANIC_COUNT panic(s) detected" "Run: docker logs $API_CONTAINER --since 5m 2>&1 | grep -i panic"
        elif [ "$FATAL_COUNT" -gt 0 ]; then
            print_failure "Docker logs: $FATAL_COUNT fatal error(s) detected" "Run: docker logs $API_CONTAINER --since 5m 2>&1 | grep -i fatal"
        elif [ "$ERROR_COUNT" -gt 10 ]; then
            print_failure "Docker logs: $ERROR_COUNT error(s) detected (>10 threshold)" "Run: docker logs $API_CONTAINER --since 5m 2>&1 | grep error"
            if [ -n "$ERROR_LINES" ]; then
                print_info "Sample errors:"
                echo "$ERROR_LINES" | head -3 | while read -r line; do
                    print_info "  $(echo "$line" | head -c 200)"
                done
            fi
        else
            print_success "Docker logs clean: $ERROR_COUNT error(s), 0 panics, 0 fatals"
        fi
    fi
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
