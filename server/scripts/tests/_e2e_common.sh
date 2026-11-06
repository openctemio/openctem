#!/bin/bash
# =============================================================================
# Shared E2E helpers — sourced by test_e2e_*.sh flow scripts.
# NOT a standalone test (underscore prefix keeps it out of run_all_e2e.sh glob).
#
#   source "$(dirname "$0")/_e2e_common.sh"
#   e2e_init "my flow name"     # sets API_URL, counters, temp files, colors
#   e2e_bootstrap_auth          # register -> login -> create-team; sets ACCESS_TOKEN/TENANT_ID
#   do_request GET /api/v1/... "" "Authorization: Bearer $ACCESS_TOKEN"
#   assert_status 200 "list findings"
#   assert_json '.total >= 0' "total present"
#   e2e_finish                  # prints summary, exits non-zero on any failure
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

PASSED=0; FAILED=0; SKIPPED=0
BODY=""; HTTP_CODE=""
ACCESS_TOKEN=""; TENANT_ID=""; USER_ID=""

e2e_init() {
    API_URL="${API_URL:-http://localhost:8080}"
    E2E_FLOW_NAME="${1:-e2e-flow}"
    TIMESTAMP=$(date +%s)
    COOKIE_JAR=$(mktemp /tmp/openctem_e2e_cookies.XXXXXX)
    RESPONSE_FILE=$(mktemp /tmp/openctem_e2e_response.XXXXXX)
    trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE} E2E FLOW: ${E2E_FLOW_NAME}${NC}"
    echo -e "${BLUE} API: ${API_URL}${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

print_test()    { echo -e "\n${YELLOW}>>> ${1}${NC}"; }
print_info()    { echo -e "     $1"; }
print_success() { echo -e "${GREEN}  PASS: $1${NC}"; PASSED=$((PASSED + 1)); }
print_failure() { echo -e "${RED}  FAIL: $1${NC}"; [ -n "$2" ] && echo -e "${RED}        $2${NC}"; FAILED=$((FAILED + 1)); }
print_skip()    { echo -e "${YELLOW}  SKIP: $1${NC}"; SKIPPED=$((SKIPPED + 1)); }
extract_json()  { echo "$1" | jq -r "$2" 2>/dev/null; }

# do_request METHOD ENDPOINT BODY [HEADER...] -> sets $HTTP_CODE, $BODY
# Auto-injects the CSRF double-submit header (X-CSRF-Token) for state-changing
# methods, read from the csrf_token cookie the login/create-team flow set.
do_request() {
    local method="$1" endpoint="$2" data="$3"; shift 3
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${API_URL}${endpoint}"
        -H "Content-Type: application/json" -c "$COOKIE_JAR" -b "$COOKIE_JAR")
    case "$method" in
        POST|PUT|PATCH|DELETE)
            local csrf; csrf=$(awk '$6=="csrf_token"{v=$7} END{print v}' "$COOKIE_JAR" 2>/dev/null)
            [ -n "$csrf" ] && curl_args+=(-H "X-CSRF-Token: $csrf")
            ;;
    esac
    local header
    for header in "$@"; do curl_args+=(-H "$header"); done
    [ -n "$data" ] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" > "$RESPONSE_FILE" 2>/dev/null
    HTTP_CODE=$(tail -n1 "$RESPONSE_FILE")
    BODY=$(sed '$d' "$RESPONSE_FILE")
}

auth_hdr() { echo "Authorization: Bearer $ACCESS_TOKEN"; }

# assert_status EXPECTED LABEL  (EXPECTED may be a |-list e.g. "200|201")
assert_status() {
    local expected="$1" label="$2"
    if echo "$HTTP_CODE" | grep -qE "^(${expected})$"; then
        print_success "$label (HTTP $HTTP_CODE)"
        return 0
    fi
    print_failure "$label" "expected HTTP $expected, got $HTTP_CODE — $(echo "$BODY" | head -c 300)"
    return 1
}

# assert_json JQ_FILTER LABEL — passes when the jq filter evaluates truthy on $BODY
assert_json() {
    local filter="$1" label="$2" out
    out=$(echo "$BODY" | jq -e "$filter" 2>/dev/null)
    if [ $? -eq 0 ] && [ "$out" != "false" ] && [ "$out" != "null" ]; then
        print_success "$label"
        return 0
    fi
    print_failure "$label" "jq '$filter' not truthy on: $(echo "$BODY" | head -c 300)"
    return 1
}

# assert_not_status FORBIDDEN LABEL — fails if HTTP_CODE matches FORBIDDEN (e.g. "500")
assert_not_status() {
    local forbidden="$1" label="$2"
    if echo "$HTTP_CODE" | grep -qE "^(${forbidden})$"; then
        print_failure "$label" "got forbidden HTTP $HTTP_CODE — $(echo "$BODY" | head -c 300)"
        return 1
    fi
    print_success "$label (HTTP $HTTP_CODE, not $forbidden)"
    return 0
}

# e2e_bootstrap_auth — register -> login -> create-first-team; sets ACCESS_TOKEN, TENANT_ID, USER_ID.
# Aborts the whole script (exit 1) if auth can't be established, since nothing downstream can run.
e2e_bootstrap_auth() {
    local email="e2e-${E2E_FLOW_NAME//[^a-z0-9]/}-${TIMESTAMP}@openctem-test.local"
    local pass="TestP@ss123!" name="E2E ${E2E_FLOW_NAME} ${TIMESTAMP}"
    local slug="e2e-${E2E_FLOW_NAME//[^a-z0-9]/}-${TIMESTAMP}"

    print_test "Bootstrap: register user"
    do_request POST /api/v1/auth/register "{\"email\":\"$email\",\"password\":\"$pass\",\"name\":\"$name\"}"
    assert_status "200|201" "register" || { print_failure "auth bootstrap aborted"; e2e_finish; }
    USER_ID=$(extract_json "$BODY" '.id')

    print_test "Bootstrap: login"
    do_request POST /api/v1/auth/login "{\"email\":\"$email\",\"password\":\"$pass\"}"
    assert_status "200" "login" || { print_failure "auth bootstrap aborted"; e2e_finish; }
    ACCESS_TOKEN=$(extract_json "$BODY" '.access_token')

    print_test "Bootstrap: create first team (tenant)"
    do_request POST /api/v1/auth/create-first-team \
        "{\"team_name\":\"$name\",\"team_slug\":\"$slug\"}" "$(auth_hdr)"
    assert_status "200|201" "create-first-team" || { print_failure "auth bootstrap aborted"; e2e_finish; }
    TENANT_ID=$(extract_json "$BODY" '.tenant_id')
    local newtok; newtok=$(extract_json "$BODY" '.access_token')
    [ -n "$newtok" ] && [ "$newtok" != "null" ] && ACCESS_TOKEN="$newtok"
    print_info "tenant_id=$TENANT_ID"
}

e2e_finish() {
    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE} RESULT: ${E2E_FLOW_NAME}${NC}"
    echo -e "  ${GREEN}PASSED: $PASSED${NC}   ${RED}FAILED: $FAILED${NC}   ${YELLOW}SKIPPED: $SKIPPED${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
    [ "$FAILED" -eq 0 ] && exit 0 || exit 1
}
