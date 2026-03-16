#!/bin/bash
# Test script for Notification History feature
# Usage: ./scripts/test_notification_history.sh <integration_id> <access_token>

set -e

API_URL="${API_URL:-http://localhost:8080}"
INTEGRATION_ID="${1:-}"
ACCESS_TOKEN="${2:-}"

if [ -z "$INTEGRATION_ID" ]; then
    echo "Usage: $0 <integration_id> <access_token>"
    echo ""
    echo "Example: $0 abc123-uuid-here eyJhbGciOiJIUzI1..."
    exit 1
fi

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Warning: No access token provided, requests may fail"
fi

AUTH_HEADER=""
if [ -n "$ACCESS_TOKEN" ]; then
    AUTH_HEADER="Authorization: Bearer $ACCESS_TOKEN"
fi

echo "=========================================="
echo "Testing Notification History"
echo "=========================================="
echo "API URL: $API_URL"
echo "Integration ID: $INTEGRATION_ID"
echo ""

# Step 1: Send a test notification
echo "1. Sending test notification..."
SEND_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/integrations/$INTEGRATION_ID/send" \
    -H "Content-Type: application/json" \
    ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
    -d '{
        "title": "Test: Notification History Verification",
        "body": "This notification tests if history is being saved correctly.",
        "severity": "high",
        "url": "https://test.openctem.io/verification"
    }')

echo "Response: $SEND_RESPONSE"
echo ""

# Step 2: Wait a moment for async processing
echo "2. Waiting 2 seconds..."
sleep 2

# Step 3: Fetch notification history
echo "3. Fetching notification history..."
HISTORY_RESPONSE=$(curl -s -X GET "$API_URL/api/v1/integrations/$INTEGRATION_ID/notification-history?limit=5" \
    ${AUTH_HEADER:+-H "$AUTH_HEADER"})

echo "History Response:"
echo "$HISTORY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$HISTORY_RESPONSE"
echo ""

# Step 4: Check if our test notification is in the history
echo "4. Checking results..."
if echo "$HISTORY_RESPONSE" | grep -q "Test: Notification History Verification"; then
    echo "SUCCESS: Test notification found in history!"
else
    echo "WARNING: Test notification NOT found in history."
    echo "This could mean:"
    echo "  - The notification was filtered by severity settings"
    echo "  - There was an error saving to database"
    echo "  - The integration is not connected"
fi

echo ""
echo "=========================================="
echo "Test completed"
echo "=========================================="
