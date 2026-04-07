#!/bin/bash
# =============================================================================
# E2E RBAC Permissions Test Script
# =============================================================================
# Tests role-based access control:
#   1. Create a second user (member role)
#   2. Verify member can read assets but not delete
#   3. Verify owner has all permissions
#   4. Test permission boundaries (read-only user tries write)
#   5. Test accessing resources without required permission
#   6. Edge cases: invalid role, self-role change
#
# Usage:
#   ./test_e2e_permissions.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TIMESTAMP=$(date +%s)
OWNER_EMAIL="e2e-owner-${TIMESTAMP}@openctem-test.local"
MEMBER_EMAIL="e2e-member-${TIMESTAMP}@openctem-test.local"
TEST_PASSWORD="SecureP@ss123!"
OWNER_NAME="Owner User"
MEMBER_NAME="Member User"
TEST_TEAM="RBAC Team ${TIMESTAMP}"
TEST_SLUG="rbac-team-${TIMESTAMP}"

COOKIE_JAR=$(mktemp /tmp/openctem_rbac_cookies.XXXXXX)
RESPONSE_FILE=$(mktemp /tmp/openctem_rbac_response.XXXXXX)
trap 'rm -f "$COOKIE_JAR" "$RESPONSE_FILE"' EXIT

PASSED=0
FAILED=0
SKIPPED=0
OWNER_TOKEN=""
MEMBER_TOKEN=""
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

auth_header() { echo "Authorization: Bearer ${1:-$OWNER_TOKEN}"; }

# =============================================================================
# Setup: Register Owner + Login + Create Team
# =============================================================================

print_header "Setup: Create Owner User & Team"

do_request POST "/api/v1/auth/register" "{\"email\":\"${OWNER_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"name\":\"${OWNER_NAME}\"}"
if [ "$HTTP_CODE" = "201" ]; then
    print_success "Register owner user"
else
    print_failure "Register owner user (HTTP $HTTP_CODE)" "$BODY"
    echo -e "${RED}Cannot proceed without auth. Exiting.${NC}"
    exit 1
fi

do_request POST "/api/v1/auth/login" "{\"email\":\"${OWNER_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
OWNER_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')
if [ -n "$OWNER_TOKEN" ]; then
    print_success "Login as owner"
else
    print_failure "Login as owner" "$BODY"
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
do_request POST "/api/v1/auth/login" "{\"email\":\"${OWNER_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
OWNER_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')

# =============================================================================
# Setup: Register Member + Invite to Team
# =============================================================================

print_header "Setup: Create Member User & Add to Team"

do_request POST "/api/v1/auth/register" "{\"email\":\"${MEMBER_EMAIL}\",\"password\":\"${TEST_PASSWORD}\",\"name\":\"${MEMBER_NAME}\"}"
if [ "$HTTP_CODE" = "201" ]; then
    print_success "Register member user"
else
    print_failure "Register member user (HTTP $HTTP_CODE)" "$BODY"
fi

# Invite member to team
print_test "Invite member to team"
do_request POST "/api/v1/tenants/${TENANT_ID}/members" \
    "{\"email\":\"${MEMBER_EMAIL}\",\"role\":\"member\"}" \
    "$(auth_header)"
MEMBER_ID=$(echo "$BODY" | jq -r '.user_id // .id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Member invited (id: $MEMBER_ID)"
else
    print_failure "Invite member (HTTP $HTTP_CODE)" "$BODY"
fi

# Login as member
do_request POST "/api/v1/auth/login" "{\"email\":\"${MEMBER_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}"
MEMBER_TOKEN=$(echo "$BODY" | jq -r '.access_token // empty')
if [ -n "$MEMBER_TOKEN" ]; then
    print_success "Login as member"
else
    print_failure "Login as member" "$BODY"
fi

# =============================================================================
# 1. Owner Full Permissions
# =============================================================================

print_header "1. Owner Full Permissions"

# Create an asset as owner
print_test "Owner: Create asset"
do_request POST "/api/v1/assets" \
    "{\"name\":\"RBAC Test Asset ${TIMESTAMP}\",\"type\":\"domain\",\"criticality\":\"high\"}" \
    "$(auth_header "$OWNER_TOKEN")"
ASSET_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    print_success "Owner created asset (id: $ASSET_ID)"
else
    print_failure "Owner create asset (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Owner: List assets"
do_request GET "/api/v1/assets" "" "$(auth_header "$OWNER_TOKEN")"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Owner can list assets"
else
    print_failure "Owner list assets (HTTP $HTTP_CODE)" "$BODY"
fi

print_test "Owner: Update asset"
if [ -n "$ASSET_ID" ]; then
    do_request PUT "/api/v1/assets/${ASSET_ID}" \
        "{\"criticality\":\"critical\"}" \
        "$(auth_header "$OWNER_TOKEN")"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Owner can update asset"
    else
        print_failure "Owner update asset (HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No asset to update"
fi

print_test "Owner: List team members"
do_request GET "/api/v1/tenants/${TENANT_ID}/members" "" "$(auth_header "$OWNER_TOKEN")"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "Owner can list team members"
else
    print_failure "Owner list members (HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# 2. Member Read Permissions
# =============================================================================

print_header "2. Member Read Permissions"

if [ -n "$MEMBER_TOKEN" ]; then
    print_test "Member: Read assets (should succeed)"
    do_request GET "/api/v1/assets" "" "$(auth_header "$MEMBER_TOKEN")"
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Member can read assets"
    else
        print_failure "Member read assets (HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Member: Read specific asset (should succeed)"
    if [ -n "$ASSET_ID" ]; then
        do_request GET "/api/v1/assets/${ASSET_ID}" "" "$(auth_header "$MEMBER_TOKEN")"
        if [ "$HTTP_CODE" = "200" ]; then
            print_success "Member can read specific asset"
        else
            print_failure "Member read specific asset (HTTP $HTTP_CODE)" "$BODY"
        fi
    else
        print_skip "No asset to read"
    fi
else
    print_skip "No member token available"
fi

# =============================================================================
# 3. Member Write/Delete Restrictions
# =============================================================================

print_header "3. Member Write/Delete Restrictions"

if [ -n "$MEMBER_TOKEN" ]; then
    print_test "Member: Delete asset (should be denied)"
    if [ -n "$ASSET_ID" ]; then
        do_request DELETE "/api/v1/assets/${ASSET_ID}" "" "$(auth_header "$MEMBER_TOKEN")"
        if [ "$HTTP_CODE" = "403" ]; then
            print_success "Member delete denied (403)"
        elif [ "$HTTP_CODE" = "401" ]; then
            print_success "Member delete denied (401)"
        else
            print_failure "Member delete should be denied (got HTTP $HTTP_CODE)" "$BODY"
        fi
    else
        print_skip "No asset to test delete"
    fi

    print_test "Member: Delete team (should be denied)"
    do_request DELETE "/api/v1/tenants/${TENANT_ID}" "" "$(auth_header "$MEMBER_TOKEN")"
    if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
        print_success "Member cannot delete team ($HTTP_CODE)"
    else
        print_failure "Member delete team should be denied (got HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Member: Manage team members (should be denied)"
    do_request POST "/api/v1/tenants/${TENANT_ID}/members" \
        "{\"email\":\"another-${TIMESTAMP}@test.local\",\"role\":\"member\"}" \
        "$(auth_header "$MEMBER_TOKEN")"
    if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
        print_success "Member cannot invite members ($HTTP_CODE)"
    else
        print_failure "Member invite should be denied (got HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No member token for restriction tests"
fi

# =============================================================================
# 4. Permission Boundaries
# =============================================================================

print_header "4. Permission Boundaries"

if [ -n "$MEMBER_TOKEN" ]; then
    print_test "Member: Access admin-only settings (should be denied)"
    do_request GET "/api/v1/tenants/${TENANT_ID}/settings" "" "$(auth_header "$MEMBER_TOKEN")"
    if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
        print_success "Member denied admin settings ($HTTP_CODE)"
    elif [ "$HTTP_CODE" = "200" ]; then
        print_failure "Member should not access admin settings"
    else
        print_failure "Unexpected response (HTTP $HTTP_CODE)" "$BODY"
    fi

    print_test "Member: Cannot change own role"
    if [ -n "$MEMBER_ID" ]; then
        do_request PUT "/api/v1/tenants/${TENANT_ID}/members/${MEMBER_ID}" \
            "{\"role\":\"owner\"}" \
            "$(auth_header "$MEMBER_TOKEN")"
        if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
            print_success "Member cannot escalate to owner ($HTTP_CODE)"
        else
            print_failure "Role self-escalation should be denied (got HTTP $HTTP_CODE)" "$BODY"
        fi
    else
        print_skip "No member ID for role change test"
    fi

    print_test "Member: Cannot manage integrations"
    do_request POST "/api/v1/integrations" \
        "{\"name\":\"Member Int\",\"category\":\"scm\",\"provider\":\"github\",\"auth_type\":\"token\",\"credentials\":\"ghp_test\"}" \
        "$(auth_header "$MEMBER_TOKEN")"
    if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
        print_success "Member denied integration creation ($HTTP_CODE)"
    else
        print_failure "Member should not create integrations (got HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "No member token for boundary tests"
fi

# =============================================================================
# 5. Access Without Authentication
# =============================================================================

print_header "5. Unauthenticated Access"

print_test "No token: Access assets"
do_request GET "/api/v1/assets" ""
if [ "$HTTP_CODE" = "401" ]; then
    print_success "No token returns 401 for assets"
else
    print_failure "No token should return 401 (got HTTP $HTTP_CODE)"
fi

print_test "No token: Access team members"
do_request GET "/api/v1/tenants/${TENANT_ID}/members" ""
if [ "$HTTP_CODE" = "401" ]; then
    print_success "No token returns 401 for members"
else
    print_failure "No token should return 401 (got HTTP $HTTP_CODE)"
fi

print_test "Expired/invalid token: Access assets"
do_request GET "/api/v1/assets" "" "Authorization: Bearer expired.invalid.token"
if [ "$HTTP_CODE" = "401" ]; then
    print_success "Invalid token returns 401"
else
    print_failure "Invalid token should return 401 (got HTTP $HTTP_CODE)"
fi

# =============================================================================
# 6. Edge Cases
# =============================================================================

print_header "6. Edge Cases"

# 6.1 Invalid role name
print_test "Edge: Invite with invalid role name"
do_request POST "/api/v1/tenants/${TENANT_ID}/members" \
    "{\"email\":\"edge-${TIMESTAMP}@test.local\",\"role\":\"superadmin\"}" \
    "$(auth_header "$OWNER_TOKEN")"
if [ "$HTTP_CODE" = "400" ]; then
    print_success "Invalid role name rejected (400)"
else
    print_failure "Invalid role should be rejected (got HTTP $HTTP_CODE)" "$BODY"
fi

# 6.2 Owner self-role change
print_test "Edge: Owner cannot demote self"
do_request GET "/api/v1/auth/me" "" "$(auth_header "$OWNER_TOKEN")"
OWNER_USER_ID=$(echo "$BODY" | jq -r '.id // empty')
if [ -n "$OWNER_USER_ID" ]; then
    do_request PUT "/api/v1/tenants/${TENANT_ID}/members/${OWNER_USER_ID}" \
        "{\"role\":\"member\"}" \
        "$(auth_header "$OWNER_TOKEN")"
    if [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "403" ]; then
        print_success "Owner self-demotion prevented ($HTTP_CODE)"
    else
        print_failure "Owner self-demotion should be prevented (got HTTP $HTTP_CODE)" "$BODY"
    fi
else
    print_skip "Could not get owner user ID"
fi

# 6.3 Remove non-existent member
print_test "Edge: Remove non-existent member"
FAKE_ID="00000000-0000-0000-0000-000000000099"
do_request DELETE "/api/v1/tenants/${TENANT_ID}/members/${FAKE_ID}" "" "$(auth_header "$OWNER_TOKEN")"
if [ "$HTTP_CODE" = "404" ]; then
    print_success "Non-existent member returns 404"
else
    print_failure "Expected 404 for non-existent member (got HTTP $HTTP_CODE)" "$BODY"
fi

# 6.4 Access other tenant's resources
print_test "Edge: Member cannot access resources without team scope"
do_request GET "/api/v1/tenants/00000000-0000-0000-0000-000000000001/members" "" "$(auth_header "$MEMBER_TOKEN")"
if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "404" ]; then
    print_success "Cross-tenant access denied ($HTTP_CODE)"
else
    print_failure "Cross-tenant access should be denied (got HTTP $HTTP_CODE)" "$BODY"
fi

# =============================================================================
# Cleanup
# =============================================================================

print_header "Cleanup"

if [ -n "$ASSET_ID" ]; then
    do_request DELETE "/api/v1/assets/${ASSET_ID}" "" "$(auth_header "$OWNER_TOKEN")"
fi
if [ -n "$MEMBER_ID" ]; then
    do_request DELETE "/api/v1/tenants/${TENANT_ID}/members/${MEMBER_ID}" "" "$(auth_header "$OWNER_TOKEN")"
fi
print_success "Cleaned up test data"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}RBAC Permissions E2E Test Summary${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${PASSED}${NC}"
echo -e "  Failed:  ${RED}${FAILED}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIPPED}${NC}"
echo -e "  Total Tests: $((PASSED + FAILED + SKIPPED))"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All permission tests passed!${NC}"
    exit 0
else
    echo -e "  ${RED}Some permission tests failed!${NC}"
    exit 1
fi
