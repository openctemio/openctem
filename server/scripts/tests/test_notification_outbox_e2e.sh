#!/bin/bash
# End-to-end test script for Notification Outbox
# This script tests the full notification flow:
# 1. Insert a test notification into the outbox (via database)
# 2. Wait for the scheduler to process it
# 3. Check the notification was sent
#
# Usage: ./scripts/test_notification_outbox_e2e.sh <tenant_id> [--docker]
#
# Prerequisites:
# - Either psql installed locally OR Docker with postgres container running
# - At least one notification integration configured for the tenant

set -e

# Configuration
DOCKER_CONTAINER="${DOCKER_CONTAINER:-api-postgres-1}"
DB_USER="${DB_USER:-openctem}"
DB_NAME="${DB_NAME:-openctem}"

TENANT_ID="${1:-}"
USE_DOCKER=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --docker)
            USE_DOCKER=true
            shift
            ;;
    esac
done

# Function to run psql command
run_psql() {
    local query="$1"
    local flags="${2:--t -A}"  # Default to -t (tuples only) -A (unaligned)

    if [ "$USE_DOCKER" = true ]; then
        docker exec -i "$DOCKER_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" $flags -c "$query" 2>/dev/null
    else
        psql "postgres://${DB_USER}:${DB_PASSWORD:-secret}@${DB_HOST:-localhost}:${DB_PORT:-5432}/${DB_NAME}" $flags -c "$query" 2>/dev/null
    fi
}

# Function to run psql and get single value (strips whitespace and newlines)
run_psql_value() {
    run_psql "$1" "-t -A" | head -1 | tr -d ' \n\r'
}

# Auto-detect: if psql not available, try docker
if ! command -v psql &> /dev/null; then
    echo "psql not found locally, using Docker..."
    USE_DOCKER=true
fi

# Verify docker container is running if using docker
if [ "$USE_DOCKER" = true ]; then
    if ! docker ps --format '{{.Names}}' | grep -q "^${DOCKER_CONTAINER}$"; then
        # Try alternative container name
        DOCKER_CONTAINER="openctemio-api-postgres-1"
        if ! docker ps --format '{{.Names}}' | grep -q "^${DOCKER_CONTAINER}$"; then
            # Try to find any postgres container
            DOCKER_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'postgres' | head -1)
            if [ -z "$DOCKER_CONTAINER" ]; then
                echo "Error: No postgres container found running"
                echo "Available containers:"
                docker ps --format '{{.Names}}'
                exit 1
            fi
        fi
    fi
    echo "Using Docker container: $DOCKER_CONTAINER"
fi

if [ -z "$TENANT_ID" ]; then
    echo "Usage: $0 <tenant_id> [--docker]"
    echo ""
    echo "Arguments:"
    echo "  tenant_id  - UUID of the tenant to test"
    echo "  --docker   - Use docker exec instead of local psql"
    echo ""
    echo "Environment variables:"
    echo "  DOCKER_CONTAINER - Docker container name (default: api-postgres-1)"
    echo "  DB_USER          - Database user (default: openctem)"
    echo "  DB_NAME          - Database name (default: openctem)"
    echo "  DB_PASSWORD      - Database password (default: secret)"
    echo "  DB_HOST          - Database host (default: localhost)"
    echo "  DB_PORT          - Database port (default: 5432)"
    echo ""
    echo "Example:"
    echo "  $0 123e4567-e89b-12d3-a456-426614174000"
    echo "  $0 123e4567-e89b-12d3-a456-426614174000 --docker"
    echo ""
    echo "To find tenant IDs:"
    if [ "$USE_DOCKER" = true ]; then
        echo "  docker exec $DOCKER_CONTAINER psql -U $DB_USER -d $DB_NAME -c 'SELECT id, name FROM tenants LIMIT 5;'"
    else
        echo "  psql \$DATABASE_URL -c 'SELECT id, name FROM tenants LIMIT 5;'"
    fi
    echo ""
    echo "Note: Make sure at least one notification integration is configured for the tenant"
    exit 1
fi

echo "=========================================="
echo "Notification Outbox E2E Test"
echo "=========================================="
echo "Tenant ID: $TENANT_ID"
echo "Mode: $([ "$USE_DOCKER" = true ] && echo "Docker ($DOCKER_CONTAINER)" || echo "Local psql")"
echo ""

# Generate unique test ID
TEST_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
TEST_TITLE="[TEST] Notification Test - $TEST_ID"

echo "1. Checking tenant has notification integrations..."
INTEGRATION_COUNT=$(run_psql_value "
    SELECT COUNT(*) FROM integrations
    WHERE tenant_id = '$TENANT_ID'
    AND category = 'notification'
    AND status = 'connected';
")

if [ -z "$INTEGRATION_COUNT" ] || [ "$INTEGRATION_COUNT" -eq 0 ] 2>/dev/null; then
    echo "   WARNING: No connected notification integrations found for tenant"
    echo "   The test will run but notifications won't be delivered"
    INTEGRATION_COUNT=0
else
    echo "   Found $INTEGRATION_COUNT connected notification integration(s)"
fi
echo ""

echo "2. Inserting test notification into outbox..."
OUTBOX_ID=$(run_psql_value "
    INSERT INTO notification_outbox (
        id,
        tenant_id,
        event_type,
        aggregate_type,
        aggregate_id,
        title,
        body,
        severity,
        url,
        status,
        retry_count,
        max_retries,
        scheduled_at,
        created_at,
        updated_at
    ) VALUES (
        gen_random_uuid(),
        '$TENANT_ID',
        'new_finding',
        'test',
        NULL,
        '$TEST_TITLE',
        'This is an automated test notification to verify the outbox processing flow. Test ID: $TEST_ID',
        'info',
        '',
        'pending',
        0,
        3,
        NOW(),
        NOW(),
        NOW()
    ) RETURNING id;
")

echo "   Outbox entry created: $OUTBOX_ID"
echo ""

echo "3. Waiting for scheduler to process (checking every 2 seconds, max 30 seconds)..."
MAX_WAIT=30
WAIT_INTERVAL=2
ELAPSED=0
STATUS=""

while [ $ELAPSED -lt $MAX_WAIT ]; do
    STATUS=$(run_psql_value "
        SELECT status FROM notification_outbox WHERE id = '$OUTBOX_ID';
    ")

    case "$STATUS" in
        "completed")
            echo "   Status: COMPLETED (after ${ELAPSED}s)"
            break
            ;;
        "failed")
            ERROR=$(run_psql "
                SELECT last_error FROM notification_outbox WHERE id = '$OUTBOX_ID';
            ")
            echo "   Status: FAILED (after ${ELAPSED}s)"
            echo "   Error: $ERROR"
            break
            ;;
        "dead")
            ERROR=$(run_psql "
                SELECT last_error FROM notification_outbox WHERE id = '$OUTBOX_ID';
            ")
            echo "   Status: DEAD (after ${ELAPSED}s)"
            echo "   Error: $ERROR"
            break
            ;;
        "processing")
            echo "   Status: PROCESSING (${ELAPSED}s elapsed)..."
            ;;
        "pending")
            echo "   Status: PENDING (${ELAPSED}s elapsed)..."
            ;;
        *)
            echo "   Status: UNKNOWN ($STATUS)"
            ;;
    esac

    sleep $WAIT_INTERVAL
    ELAPSED=$((ELAPSED + WAIT_INTERVAL))
done

if [ "$STATUS" = "pending" ] || [ "$STATUS" = "processing" ]; then
    echo ""
    echo "   WARNING: Notification still not processed after ${MAX_WAIT}s"
    echo "   The scheduler might not be running or processing is slow"
fi
echo ""

echo "4. Fetching final outbox entry details..."
run_psql "
    SELECT
        id,
        status,
        retry_count,
        last_error,
        scheduled_at,
        processed_at,
        created_at
    FROM notification_outbox
    WHERE id = '$OUTBOX_ID';
" ""
echo ""

echo "5. Checking notification history..."
HISTORY_COUNT=$(run_psql_value "
    SELECT COUNT(*) FROM notification_history
    WHERE tenant_id = '$TENANT_ID'
    AND title = '$TEST_TITLE';
")

if [ -n "$HISTORY_COUNT" ] && [ "$HISTORY_COUNT" -gt 0 ] 2>/dev/null; then
    echo "   Found $HISTORY_COUNT notification history entries"
    echo ""
    run_psql "
        SELECT
            id,
            integration_id,
            status,
            error_message,
            sent_at
        FROM notification_history
        WHERE tenant_id = '$TENANT_ID'
        AND title = '$TEST_TITLE'
        ORDER BY sent_at DESC
        LIMIT 5;
    " ""
else
    HISTORY_COUNT=0
    echo "   No notification history entries found"
    echo "   This could mean:"
    echo "   - No integrations are configured"
    echo "   - Integrations don't match event_type/severity filters"
    echo "   - Processing hasn't completed yet"
fi
echo ""

echo "6. Cleanup - Deleting test entries..."
run_psql "
    DELETE FROM notification_history WHERE title = '$TEST_TITLE';
    DELETE FROM notification_outbox WHERE id = '$OUTBOX_ID';
" "" > /dev/null 2>&1
echo "   Test entries cleaned up"
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Outbox ID: $OUTBOX_ID"
echo "Final Status: $STATUS"
echo "Integrations Found: $INTEGRATION_COUNT"
echo "History Entries: $HISTORY_COUNT"

if [ "$STATUS" = "completed" ] && [ "$HISTORY_COUNT" -gt 0 ]; then
    echo ""
    echo "Result: SUCCESS - Notification was processed and sent"
    exit 0
elif [ "$STATUS" = "completed" ] && [ "$HISTORY_COUNT" -eq 0 ]; then
    echo ""
    echo "Result: PARTIAL - Outbox processed but no history (check integration filters)"
    exit 0
elif [ "$STATUS" = "failed" ] || [ "$STATUS" = "dead" ]; then
    echo ""
    echo "Result: FAILED - Check error message above"
    exit 1
else
    echo ""
    echo "Result: TIMEOUT - Scheduler might not be running"
    exit 1
fi
