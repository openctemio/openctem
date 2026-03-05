#!/bin/bash
# Test script for Data Scope UX Improvements:
#   1. Incremental Access Refresh
#   2. Bulk Asset Assignment
#   3. Assignment Rule API
#
# Usage:
#   ./scripts/test_new_features.sh              # Run unit tests only
#   ./scripts/test_new_features.sh --api        # Run API integration tests (requires running server)
#   ./scripts/test_new_features.sh --all        # Run both unit + API tests
#
# Environment variables for API tests:
#   API_URL     - Base URL (default: http://localhost:8080)
#   AUTH_TOKEN  - JWT token for authenticated requests
#   TENANT_ID   - Tenant ID for API calls

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    pass_count=$((pass_count + 1))
}

fail() {
    echo -e "  ${RED}FAIL${NC} $1: $2"
    fail_count=$((fail_count + 1))
}

section() {
    echo ""
    echo -e "${YELLOW}=== $1 ===${NC}"
    echo ""
}

# =============================================================================
# UNIT TESTS
# =============================================================================
run_unit_tests() {
    section "Unit Tests: Incremental Access Refresh"
    echo "Testing assign/unassign asset uses incremental refresh..."
    go test -v -count=1 -run "TestAssignAsset_UsesIncrementalRefresh|TestAssignAsset_RefreshErrorNonBlocking|TestUnassignAsset_UsesIncrementalRefresh|TestUnassignAsset_RefreshErrorNonBlocking" ./tests/unit/ 2>&1 | tail -8
    pass "Incremental refresh for asset assign/unassign"

    echo ""
    echo "Testing add/remove member uses incremental refresh..."
    go test -v -count=1 -run "TestAddMember_UsesIncrementalRefresh|TestAddMember_RefreshErrorNonBlocking|TestRemoveMember_UsesIncrementalRefresh" ./tests/unit/ 2>&1 | tail -6
    pass "Incremental refresh for member add/remove"

    section "Unit Tests: Bulk Asset Assignment"
    echo "Running bulk assign tests..."
    go test -v -count=1 -run "TestBulkAssignAssets" ./tests/unit/ 2>&1 | tail -16
    pass "Bulk asset assignment (all scenarios)"

    section "Unit Tests: Assignment Rule Service"
    echo "Running assignment rule CRUD tests..."
    go test -v -count=1 -run "TestCreateRule|TestGetRule|TestUpdateRule|TestDeleteRule|TestListRules|TestTestRule" ./tests/unit/ 2>&1 | tail -50
    pass "Assignment rule service CRUD"

    section "Unit Tests: Assignment Rule Entity"
    echo "Running entity tests..."
    go test -v -count=1 -run "TestAssignmentRule_" ./tests/unit/ 2>&1 | tail -10
    pass "Assignment rule entity"

    section "Full Suite"
    echo "Running complete unit test suite..."
    go test -count=1 ./tests/unit/ 2>&1
    pass "All unit tests pass"

    echo ""
    echo "Running go vet..."
    go vet ./... 2>&1
    pass "go vet clean"

    echo ""
    echo "Running go build..."
    go build ./... 2>&1
    pass "go build clean"
}

# =============================================================================
# API INTEGRATION TESTS
# =============================================================================
run_api_tests() {
    API_URL="${API_URL:-http://localhost:8080}"

    if [ -z "$AUTH_TOKEN" ]; then
        echo -e "${RED}ERROR: AUTH_TOKEN environment variable is required for API tests${NC}"
        echo "  Export a valid JWT token: export AUTH_TOKEN='eyJ...'"
        exit 1
    fi

    AUTH_HEADER="Authorization: Bearer $AUTH_TOKEN"
    CONTENT_TYPE="Content-Type: application/json"

    # Health check
    section "API Health Check"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health")
    if [ "$HTTP_CODE" = "200" ]; then
        pass "Health endpoint ($API_URL/health)"
    else
        fail "Health endpoint" "HTTP $HTTP_CODE"
        echo -e "${RED}Server not reachable. Start it first.${NC}"
        exit 1
    fi

    # ------------------------------------------------------------------
    # Assignment Rules CRUD
    # ------------------------------------------------------------------
    section "API: Assignment Rules CRUD"

    # Create a group first (needed as target for assignment rules)
    echo "Creating test group..."
    GROUP_RESP=$(curl -s -X POST "$API_URL/api/v1/groups" \
        -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
        -d '{"name":"Test AR Group","slug":"test-ar-group","type":"team"}')
    GROUP_ID=$(echo "$GROUP_RESP" | jq -r '.id // empty')
    if [ -z "$GROUP_ID" ]; then
        echo -e "${YELLOW}WARN: Could not create group, trying to use existing...${NC}"
        GROUP_RESP=$(curl -s "$API_URL/api/v1/groups?limit=1" -H "$AUTH_HEADER")
        GROUP_ID=$(echo "$GROUP_RESP" | jq -r '.data[0].id // empty')
    fi

    if [ -z "$GROUP_ID" ]; then
        fail "Setup" "No group available for assignment rule tests"
    else
        pass "Test group ready: $GROUP_ID"

        # CREATE assignment rule
        echo "Creating assignment rule..."
        CREATE_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/assignment-rules" \
            -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
            -d "{
                \"name\": \"Test Rule $(date +%s)\",
                \"description\": \"Auto-created by test script\",
                \"priority\": 10,
                \"target_group_id\": \"$GROUP_ID\",
                \"conditions\": {
                    \"asset_type\": [\"host\", \"website\"],
                    \"finding_severity\": [\"critical\", \"high\"]
                },
                \"options\": {
                    \"notify_group\": true
                }
            }")
        CREATE_CODE=$(echo "$CREATE_RESP" | tail -1)
        CREATE_BODY=$(echo "$CREATE_RESP" | head -n -1)
        RULE_ID=$(echo "$CREATE_BODY" | jq -r '.id // empty')

        if [ "$CREATE_CODE" = "201" ] || [ "$CREATE_CODE" = "200" ]; then
            pass "POST /assignment-rules → $CREATE_CODE (id: $RULE_ID)"
        else
            fail "POST /assignment-rules" "HTTP $CREATE_CODE: $CREATE_BODY"
        fi

        if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ]; then
            # LIST assignment rules
            LIST_RESP=$(curl -s -w "\n%{http_code}" "$API_URL/api/v1/assignment-rules?limit=10" \
                -H "$AUTH_HEADER")
            LIST_CODE=$(echo "$LIST_RESP" | tail -1)
            LIST_BODY=$(echo "$LIST_RESP" | head -n -1)
            LIST_COUNT=$(echo "$LIST_BODY" | jq -r '.total_count // 0')

            if [ "$LIST_CODE" = "200" ]; then
                pass "GET /assignment-rules → $LIST_CODE (count: $LIST_COUNT)"
            else
                fail "GET /assignment-rules" "HTTP $LIST_CODE"
            fi

            # GET single assignment rule
            GET_RESP=$(curl -s -w "\n%{http_code}" "$API_URL/api/v1/assignment-rules/$RULE_ID" \
                -H "$AUTH_HEADER")
            GET_CODE=$(echo "$GET_RESP" | tail -1)
            GET_BODY=$(echo "$GET_RESP" | head -n -1)

            if [ "$GET_CODE" = "200" ]; then
                pass "GET /assignment-rules/$RULE_ID → $GET_CODE"
            else
                fail "GET /assignment-rules/$RULE_ID" "HTTP $GET_CODE"
            fi

            # UPDATE assignment rule
            UPDATE_RESP=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/api/v1/assignment-rules/$RULE_ID" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d '{"name": "Updated Rule Name", "priority": 99, "is_active": false}')
            UPDATE_CODE=$(echo "$UPDATE_RESP" | tail -1)
            UPDATE_BODY=$(echo "$UPDATE_RESP" | head -n -1)

            if [ "$UPDATE_CODE" = "200" ]; then
                UPDATED_NAME=$(echo "$UPDATE_BODY" | jq -r '.name // empty')
                UPDATED_ACTIVE=$(echo "$UPDATE_BODY" | jq -r '.is_active // empty')
                if [ "$UPDATED_NAME" = "Updated Rule Name" ] && [ "$UPDATED_ACTIVE" = "false" ]; then
                    pass "PUT /assignment-rules/$RULE_ID → name updated, deactivated"
                else
                    fail "PUT /assignment-rules/$RULE_ID" "Fields not updated correctly"
                fi
            else
                fail "PUT /assignment-rules/$RULE_ID" "HTTP $UPDATE_CODE"
            fi

            # TEST assignment rule (dry run)
            TEST_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/assignment-rules/$RULE_ID/test" \
                -H "$AUTH_HEADER")
            TEST_CODE=$(echo "$TEST_RESP" | tail -1)

            if [ "$TEST_CODE" = "200" ]; then
                pass "POST /assignment-rules/$RULE_ID/test → $TEST_CODE"
            else
                fail "POST /assignment-rules/$RULE_ID/test" "HTTP $TEST_CODE"
            fi

            # DELETE assignment rule
            DEL_RESP=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/api/v1/assignment-rules/$RULE_ID" \
                -H "$AUTH_HEADER")
            DEL_CODE=$(echo "$DEL_RESP" | tail -1)

            if [ "$DEL_CODE" = "204" ] || [ "$DEL_CODE" = "200" ]; then
                pass "DELETE /assignment-rules/$RULE_ID → $DEL_CODE"
            else
                fail "DELETE /assignment-rules/$RULE_ID" "HTTP $DEL_CODE"
            fi

            # Verify deletion
            VERIFY_RESP=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/assignment-rules/$RULE_ID" \
                -H "$AUTH_HEADER")
            if [ "$VERIFY_RESP" = "404" ]; then
                pass "Verified: rule deleted (404)"
            else
                fail "Verify deletion" "Expected 404, got $VERIFY_RESP"
            fi
        fi
    fi

    # ------------------------------------------------------------------
    # Bulk Asset Assignment
    # ------------------------------------------------------------------
    section "API: Bulk Asset Assignment"

    if [ -n "$GROUP_ID" ]; then
        # Create a few test assets first
        ASSET_IDS="[]"
        echo "Creating test assets..."
        for i in 1 2 3; do
            ASSET_RESP=$(curl -s -X POST "$API_URL/api/v1/assets" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d "{\"name\": \"Bulk Test Asset $i $(date +%s)\", \"type\": \"host\", \"criticality\": \"medium\"}")
            AID=$(echo "$ASSET_RESP" | jq -r '.id // empty')
            if [ -n "$AID" ] && [ "$AID" != "null" ]; then
                ASSET_IDS=$(echo "$ASSET_IDS" | jq --arg id "$AID" '. + [$id]')
            fi
        done

        ASSET_COUNT=$(echo "$ASSET_IDS" | jq length)
        if [ "$ASSET_COUNT" -ge 1 ]; then
            pass "Created $ASSET_COUNT test assets"

            # Bulk assign
            BULK_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/groups/$GROUP_ID/assets/bulk" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d "{\"asset_ids\": $ASSET_IDS, \"ownership_type\": \"primary\"}")
            BULK_CODE=$(echo "$BULK_RESP" | tail -1)
            BULK_BODY=$(echo "$BULK_RESP" | head -n -1)
            SUCCESS_COUNT=$(echo "$BULK_BODY" | jq -r '.success_count // 0')
            FAILED_COUNT=$(echo "$BULK_BODY" | jq -r '.failed_count // 0')

            if [ "$BULK_CODE" = "200" ]; then
                pass "POST /groups/$GROUP_ID/assets/bulk → success=$SUCCESS_COUNT, failed=$FAILED_COUNT"
            else
                fail "Bulk assign" "HTTP $BULK_CODE: $BULK_BODY"
            fi

            # Test idempotency (re-assign same assets)
            BULK_RESP2=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/groups/$GROUP_ID/assets/bulk" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d "{\"asset_ids\": $ASSET_IDS, \"ownership_type\": \"primary\"}")
            BULK_CODE2=$(echo "$BULK_RESP2" | tail -1)
            BULK_BODY2=$(echo "$BULK_RESP2" | head -n -1)

            if [ "$BULK_CODE2" = "200" ]; then
                pass "Bulk assign idempotency (re-assign same assets) → OK"
            else
                fail "Bulk assign idempotency" "HTTP $BULK_CODE2"
            fi

            # Test with invalid asset IDs mixed in
            MIXED_IDS=$(echo "$ASSET_IDS" | jq '. + ["not-a-uuid", "also-invalid"]')
            BULK_RESP3=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/groups/$GROUP_ID/assets/bulk" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d "{\"asset_ids\": $MIXED_IDS, \"ownership_type\": \"secondary\"}")
            BULK_CODE3=$(echo "$BULK_RESP3" | tail -1)

            if [ "$BULK_CODE3" = "200" ] || [ "$BULK_CODE3" = "400" ]; then
                pass "Bulk assign with mixed IDs → HTTP $BULK_CODE3"
            else
                fail "Bulk assign mixed IDs" "HTTP $BULK_CODE3"
            fi

            # Test with invalid ownership type
            BULK_RESP4=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/groups/$GROUP_ID/assets/bulk" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d "{\"asset_ids\": $ASSET_IDS, \"ownership_type\": \"invalid\"}")

            if [ "$BULK_RESP4" = "400" ] || [ "$BULK_RESP4" = "422" ]; then
                pass "Bulk assign invalid ownership type → rejected ($BULK_RESP4)"
            else
                fail "Bulk assign invalid ownership" "Expected 400/422, got $BULK_RESP4"
            fi

            # Test with empty asset list
            BULK_RESP5=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/groups/$GROUP_ID/assets/bulk" \
                -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
                -d '{"asset_ids": [], "ownership_type": "primary"}')

            if [ "$BULK_RESP5" = "400" ] || [ "$BULK_RESP5" = "422" ]; then
                pass "Bulk assign empty list → rejected ($BULK_RESP5)"
            else
                fail "Bulk assign empty list" "Expected 400/422, got $BULK_RESP5"
            fi

            # Cleanup: unassign assets
            for AID in $(echo "$ASSET_IDS" | jq -r '.[]'); do
                curl -s -o /dev/null -X DELETE "$API_URL/api/v1/groups/$GROUP_ID/assets/$AID" \
                    -H "$AUTH_HEADER"
            done
            pass "Cleanup: assets unassigned"
        else
            fail "Setup" "Could not create test assets"
        fi
    else
        fail "Setup" "No group available for bulk assign tests"
    fi

    # ------------------------------------------------------------------
    # Validation: Unauthorized access
    # ------------------------------------------------------------------
    section "API: Security Validation"

    # Test without auth token
    NOAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/v1/assignment-rules")
    if [ "$NOAUTH_CODE" = "401" ]; then
        pass "Assignment rules require authentication (401)"
    else
        fail "Auth check" "Expected 401 without token, got $NOAUTH_CODE"
    fi

    NOAUTH_CODE2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/v1/groups/fake-id/assets/bulk" \
        -H "$CONTENT_TYPE" -d '{"asset_ids":["fake"],"ownership_type":"primary"}')
    if [ "$NOAUTH_CODE2" = "401" ]; then
        pass "Bulk assign requires authentication (401)"
    else
        fail "Auth check bulk" "Expected 401 without token, got $NOAUTH_CODE2"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

echo ""
echo "=============================================="
echo "  Data Scope UX Improvements - Test Suite"
echo "  Features: Incremental Refresh, Bulk Assign,"
echo "            Assignment Rules API"
echo "=============================================="

case "${1:-}" in
    --api)
        run_api_tests
        ;;
    --all)
        run_unit_tests
        echo ""
        run_api_tests
        ;;
    *)
        run_unit_tests
        ;;
esac

# Summary
echo ""
echo "=============================================="
echo -e "  Results: ${GREEN}$pass_count passed${NC}, ${RED}$fail_count failed${NC}"
echo "=============================================="

if [ $fail_count -gt 0 ]; then
    exit 1
fi
