#!/bin/bash
# Test script for Notification Outbox Tenant API
# Usage: ./scripts/test_notification_outbox.sh <access_token>
#
# Note: Requires integrations:notifications:read/write permissions
# Access token must be tenant-scoped (contains tenant_id)

set -e

API_URL="${API_URL:-http://localhost:8080}"
ACCESS_TOKEN="${1:-}"

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Usage: $0 <access_token>"
    echo ""
    echo "Example: $0 eyJhbGciOiJIUzI1..."
    echo ""
    echo "Note: Token must be tenant-scoped (contains tenant_id)"
    echo "      and have integrations:notifications:read permission"
    exit 1
fi

AUTH_HEADER="Authorization: Bearer $ACCESS_TOKEN"

echo "=========================================="
echo "Testing Notification Outbox Tenant API"
echo "=========================================="
echo "API URL: $API_URL"
echo ""

# Step 1: Get outbox statistics
echo "1. Getting outbox statistics..."
STATS_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/v1/notification-outbox/stats" \
    -H "$AUTH_HEADER")

HTTP_CODE=$(echo "$STATS_RESPONSE" | tail -n1)
STATS_BODY=$(echo "$STATS_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "Statistics:"
    echo "$STATS_BODY" | python3 -m json.tool 2>/dev/null || echo "$STATS_BODY"
    echo ""

    # Extract counts
    PENDING=$(echo "$STATS_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('pending', 0))" 2>/dev/null || echo "0")
    TOTAL=$(echo "$STATS_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total', 0))" 2>/dev/null || echo "0")
    echo "Summary: $PENDING pending, $TOTAL total"
else
    echo "Error response: $STATS_BODY"
fi
echo ""

# Step 2: List outbox entries
echo "2. Listing outbox entries (first page)..."
LIST_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/v1/notification-outbox?page=1&page_size=5" \
    -H "$AUTH_HEADER")

HTTP_CODE=$(echo "$LIST_RESPONSE" | tail -n1)
LIST_BODY=$(echo "$LIST_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "Entries:"
    echo "$LIST_BODY" | python3 -m json.tool 2>/dev/null || echo "$LIST_BODY"
else
    echo "Error response: $LIST_BODY"
fi
echo ""

# Step 3: List entries filtered by status (pending)
echo "3. Listing pending entries..."
PENDING_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/v1/notification-outbox?status=pending&page_size=5" \
    -H "$AUTH_HEADER")

HTTP_CODE=$(echo "$PENDING_RESPONSE" | tail -n1)
PENDING_BODY=$(echo "$PENDING_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "Pending Entries:"
    echo "$PENDING_BODY" | python3 -m json.tool 2>/dev/null || echo "$PENDING_BODY"
else
    echo "Error response: $PENDING_BODY"
fi
echo ""

# Step 4: List failed entries
echo "4. Listing failed entries..."
FAILED_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/v1/notification-outbox?status=failed&page_size=5" \
    -H "$AUTH_HEADER")

HTTP_CODE=$(echo "$FAILED_RESPONSE" | tail -n1)
FAILED_BODY=$(echo "$FAILED_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    # Extract first failed entry ID for retry test
    FAILED_ID=$(echo "$FAILED_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); data=d.get('data',[]); print(data[0]['id'] if data else '')" 2>/dev/null || echo "")

    echo "Failed Entries:"
    echo "$FAILED_BODY" | python3 -m json.tool 2>/dev/null || echo "$FAILED_BODY"

    # Step 5: If there's a failed entry, try to retry it
    if [ -n "$FAILED_ID" ]; then
        echo ""
        echo "5. Retrying failed entry: $FAILED_ID..."
        RETRY_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/notification-outbox/$FAILED_ID/retry" \
            -H "$AUTH_HEADER")

        HTTP_CODE=$(echo "$RETRY_RESPONSE" | tail -n1)
        RETRY_BODY=$(echo "$RETRY_RESPONSE" | sed '$d')

        echo "HTTP Status: $HTTP_CODE"
        if [ "$HTTP_CODE" = "200" ]; then
            echo "Entry retried successfully:"
            echo "$RETRY_BODY" | python3 -m json.tool 2>/dev/null || echo "$RETRY_BODY"
        else
            echo "Error response: $RETRY_BODY"
        fi
    else
        echo ""
        echo "5. No failed entries to retry (skipping retry test)"
    fi
else
    echo "Error response: $FAILED_BODY"
fi
echo ""

# Step 6: Get a single entry (if any exist)
echo "6. Testing get single entry..."
# Extract first entry ID from previous list
FIRST_ID=$(echo "$LIST_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); data=d.get('data',[]); print(data[0]['id'] if data else '')" 2>/dev/null || echo "")

if [ -n "$FIRST_ID" ]; then
    GET_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/v1/notification-outbox/$FIRST_ID" \
        -H "$AUTH_HEADER")

    HTTP_CODE=$(echo "$GET_RESPONSE" | tail -n1)
    GET_BODY=$(echo "$GET_RESPONSE" | sed '$d')

    echo "Entry ID: $FIRST_ID"
    echo "HTTP Status: $HTTP_CODE"
    if [ "$HTTP_CODE" = "200" ]; then
        echo "Entry details:"
        echo "$GET_BODY" | python3 -m json.tool 2>/dev/null || echo "$GET_BODY"
    else
        echo "Error response: $GET_BODY"
    fi
else
    echo "No entries found to get (skipping get test)"
fi
echo ""

echo "=========================================="
echo "Test completed"
echo "=========================================="
echo ""
echo "Summary of available endpoints:"
echo "  GET  /api/v1/notification-outbox          - List entries"
echo "  GET  /api/v1/notification-outbox/stats    - Get statistics"
echo "  GET  /api/v1/notification-outbox/{id}     - Get single entry"
echo "  POST /api/v1/notification-outbox/{id}/retry - Retry failed entry"
echo "  DELETE /api/v1/notification-outbox/{id}   - Delete entry"
