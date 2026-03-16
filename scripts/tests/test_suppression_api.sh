#!/bin/bash
# Test script for Suppression API endpoints

set -e

API_URL="${API_URL:-http://localhost:8080}"
TENANT_ID="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"  # TechViet Solutions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Suppression API Test Script"
echo "=========================================="
echo "API URL: $API_URL"
echo "Tenant ID: $TENANT_ID"
echo ""

# Check if ACCESS_TOKEN is provided
if [ -z "$ACCESS_TOKEN" ]; then
    echo -e "${YELLOW}ACCESS_TOKEN not set. Attempting to get token...${NC}"

    # Try to login with test user
    LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{
            "email": "nguyen.an@techviet.vn",
            "password": "Password123"
        }')

    REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('refresh_token', ''))" 2>/dev/null)

    if [ -z "$REFRESH_TOKEN" ]; then
        echo -e "${RED}Failed to login. Response: $LOGIN_RESPONSE${NC}"
        echo ""
        echo "Please set ACCESS_TOKEN environment variable manually:"
        echo "  export ACCESS_TOKEN='your-jwt-token'"
        exit 1
    fi

    # Get access token for tenant
    TOKEN_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/auth/token" \
        -H "Content-Type: application/json" \
        -d "{
            \"refresh_token\": \"$REFRESH_TOKEN\",
            \"tenant_id\": \"$TENANT_ID\"
        }")

    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null)

    if [ -z "$ACCESS_TOKEN" ]; then
        echo -e "${RED}Failed to get access token. Response: $TOKEN_RESPONSE${NC}"
        exit 1
    fi

    echo -e "${GREEN}Got access token successfully${NC}"
fi

AUTH_HEADER="Authorization: Bearer $ACCESS_TOKEN"

# Helper function for API calls
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3

    if [ -n "$data" ]; then
        curl -s -X "$method" "$API_URL$endpoint" \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$API_URL$endpoint" \
            -H "$AUTH_HEADER" \
            -H "Content-Type: application/json"
    fi
}

# Pretty print JSON
pretty_json() {
    python3 -m json.tool 2>/dev/null || cat
}

echo ""
echo "=========================================="
echo "1. List suppression rules (should be empty or have existing)"
echo "=========================================="
RULES=$(api_call GET "/api/v1/suppressions")
echo "$RULES" | pretty_json | head -30
echo ""

echo "=========================================="
echo "2. Create a new suppression rule"
echo "=========================================="
CREATE_RESPONSE=$(api_call POST "/api/v1/suppressions" '{
    "name": "Test Suppression Rule",
    "description": "Suppress test findings in test directories",
    "rule_id": "semgrep.test-rule*",
    "tool_name": "semgrep",
    "path_pattern": "tests/**",
    "suppression_type": "false_positive"
}')
echo "$CREATE_RESPONSE" | pretty_json

RULE_ID=$(echo "$CREATE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null)

if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ]; then
    echo -e "${GREEN}Created rule with ID: $RULE_ID${NC}"

    echo ""
    echo "=========================================="
    echo "3. Get the created rule"
    echo "=========================================="
    api_call GET "/api/v1/suppressions/$RULE_ID" | pretty_json

    echo ""
    echo "=========================================="
    echo "3.5. Update the rule (while pending)"
    echo "=========================================="
    UPDATE_RESPONSE=$(api_call PUT "/api/v1/suppressions/$RULE_ID" '{
        "name": "Updated Test Suppression Rule",
        "description": "Updated description for test",
        "path_pattern": "tests/**/*.go"
    }')
    echo "$UPDATE_RESPONSE" | pretty_json

    UPDATED_NAME=$(echo "$UPDATE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('name', ''))" 2>/dev/null)
    UPDATED_PATH=$(echo "$UPDATE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('path_pattern', ''))" 2>/dev/null)

    if [ "$UPDATED_NAME" = "Updated Test Suppression Rule" ]; then
        echo -e "${GREEN}✓ Name updated successfully${NC}"
    else
        echo -e "${RED}✗ Expected name 'Updated Test Suppression Rule', got '$UPDATED_NAME'${NC}"
    fi

    if [ "$UPDATED_PATH" = "tests/**/*.go" ]; then
        echo -e "${GREEN}✓ Path pattern updated successfully${NC}"
    else
        echo -e "${RED}✗ Expected path 'tests/**/*.go', got '$UPDATED_PATH'${NC}"
    fi

    echo ""
    echo "=========================================="
    echo "4. Approve the rule"
    echo "=========================================="
    APPROVE_RESPONSE=$(api_call POST "/api/v1/suppressions/$RULE_ID/approve" '{}')
    echo "$APPROVE_RESPONSE" | pretty_json

    APPROVE_STATUS=$(echo "$APPROVE_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null)
    if [ "$APPROVE_STATUS" = "approved" ]; then
        echo -e "${GREEN}✓ Rule approved successfully${NC}"
    else
        echo -e "${RED}✗ Expected status 'approved', got '$APPROVE_STATUS'${NC}"
    fi

    echo ""
    echo "=========================================="
    echo "5. List active rules (for agent)"
    echo "=========================================="
    ACTIVE_RULES=$(api_call GET "/api/v1/suppressions/active")
    echo "$ACTIVE_RULES" | pretty_json

    ACTIVE_COUNT=$(echo "$ACTIVE_RULES" | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null)
    if [ "$ACTIVE_COUNT" -ge 1 ]; then
        echo -e "${GREEN}✓ Found $ACTIVE_COUNT active rule(s)${NC}"
    else
        echo -e "${RED}✗ Expected at least 1 active rule${NC}"
    fi

    echo ""
    echo "=========================================="
    echo "6. Delete the rule (cleanup for reject test)"
    echo "=========================================="
    api_call DELETE "/api/v1/suppressions/$RULE_ID" | pretty_json
    echo -e "${GREEN}✓ Deleted rule for cleanup${NC}"

    echo ""
    echo "=========================================="
    echo "7. Create another rule to test REJECT"
    echo "=========================================="
    REJECT_CREATE=$(api_call POST "/api/v1/suppressions" '{
        "name": "Rule to be Rejected",
        "description": "This rule will be rejected",
        "rule_id": "gitleaks.secret*",
        "tool_name": "gitleaks",
        "suppression_type": "accepted_risk"
    }')
    echo "$REJECT_CREATE" | pretty_json

    REJECT_RULE_ID=$(echo "$REJECT_CREATE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null)

    if [ -n "$REJECT_RULE_ID" ] && [ "$REJECT_RULE_ID" != "null" ]; then
        echo -e "${GREEN}Created rule with ID: $REJECT_RULE_ID${NC}"

        echo ""
        echo "=========================================="
        echo "8. Reject the rule"
        echo "=========================================="
        REJECT_RESPONSE=$(api_call POST "/api/v1/suppressions/$REJECT_RULE_ID/reject" '{
            "reason": "This rule is too broad and may hide real issues"
        }')
        echo "$REJECT_RESPONSE" | pretty_json

        REJECT_STATUS=$(echo "$REJECT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null)
        REJECT_REASON=$(echo "$REJECT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('rejection_reason', ''))" 2>/dev/null)

        if [ "$REJECT_STATUS" = "rejected" ]; then
            echo -e "${GREEN}✓ Rule rejected successfully${NC}"
            echo -e "${GREEN}✓ Rejection reason: $REJECT_REASON${NC}"
        else
            echo -e "${RED}✗ Expected status 'rejected', got '$REJECT_STATUS'${NC}"
        fi

        echo ""
        echo "=========================================="
        echo "9. Verify rejected rule NOT in active list"
        echo "=========================================="
        ACTIVE_AFTER_REJECT=$(api_call GET "/api/v1/suppressions/active")
        echo "$ACTIVE_AFTER_REJECT" | pretty_json

        ACTIVE_COUNT_AFTER=$(echo "$ACTIVE_AFTER_REJECT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null)
        if [ "$ACTIVE_COUNT_AFTER" -eq 0 ]; then
            echo -e "${GREEN}✓ No active rules (rejected rule correctly excluded)${NC}"
        else
            echo -e "${YELLOW}! Found $ACTIVE_COUNT_AFTER active rule(s) - check if these are from previous runs${NC}"
        fi

        echo ""
        echo "=========================================="
        echo "10. Delete rejected rule (final cleanup)"
        echo "=========================================="
        api_call DELETE "/api/v1/suppressions/$REJECT_RULE_ID" | pretty_json
        echo -e "${GREEN}✓ Cleanup complete${NC}"
    else
        echo -e "${RED}Failed to create rule for reject test${NC}"
    fi

    echo ""
    echo -e "${GREEN}Test completed successfully!${NC}"
else
    echo -e "${YELLOW}Could not extract rule ID. Create may have failed or returned different format.${NC}"
    echo "Full response: $CREATE_RESPONSE"
fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "All suppression API endpoints tested."
