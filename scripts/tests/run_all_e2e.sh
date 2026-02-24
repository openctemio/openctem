#!/bin/bash
# =============================================================================
# Run All E2E Test Scripts
# =============================================================================
# Runs all test_e2e_*.sh scripts with 62s delay between each to avoid
# auth rate limiting (3 registrations/min per IP).
#
# Usage:
#   ./run_all_e2e.sh [API_URL]
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${BLUE}=============================================================================="
echo -e "Run All E2E Tests"
echo -e "==============================================================================${NC}"
echo ""
echo "  API URL: $API_URL"
echo "  Script Dir: $SCRIPT_DIR"
echo ""

# Collect all E2E test scripts
SCRIPTS=($(ls "$SCRIPT_DIR"/test_e2e_*.sh 2>/dev/null | sort))
TOTAL_SCRIPTS=${#SCRIPTS[@]}

if [ "$TOTAL_SCRIPTS" -eq 0 ]; then
    echo -e "${RED}No E2E test scripts found!${NC}"
    exit 1
fi

echo "  Found $TOTAL_SCRIPTS E2E test scripts"
echo ""

SUITE_PASSED=0
SUITE_FAILED=0
SUITE_RESULTS=()
START_TIME=$(date +%s)

for i in "${!SCRIPTS[@]}"; do
    script="${SCRIPTS[$i]}"
    script_name=$(basename "$script" .sh)
    idx=$((i + 1))

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[$idx/$TOTAL_SCRIPTS] Running: $script_name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Wait for rate limit (skip for first script)
    if [ "$i" -gt 0 ]; then
        echo -e "${YELLOW}  Waiting 62s for rate limit...${NC}"
        sleep 62
    fi

    # Run script, capture output and exit code
    OUTPUT=$(bash "$script" "$API_URL" 2>&1)
    EXIT_CODE=$?

    # Extract summary line
    PASSED=$(echo "$OUTPUT" | grep -oP 'Passed: \K\d+' | tail -1)
    FAILED=$(echo "$OUTPUT" | grep -oP 'Failed: \K\d+' | tail -1)
    TOTAL=$(echo "$OUTPUT" | grep -oP 'Total Tests: \K\d+' | tail -1)

    if [ "$EXIT_CODE" -eq 0 ]; then
        echo -e "${GREEN}  ✓ $script_name: $PASSED/$TOTAL passed${NC}"
        SUITE_PASSED=$((SUITE_PASSED + 1))
        SUITE_RESULTS+=("${GREEN}✓ $script_name: $PASSED/$TOTAL passed${NC}")
    else
        echo -e "${RED}  ✗ $script_name: $PASSED/$TOTAL passed, $FAILED failed${NC}"
        # Show failed tests
        echo "$OUTPUT" | grep "FAILED:" | head -5
        SUITE_FAILED=$((SUITE_FAILED + 1))
        SUITE_RESULTS+=("${RED}✗ $script_name: $PASSED/$TOTAL passed, $FAILED failed${NC}")
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo -e "${BLUE}=============================================================================="
echo -e "Overall E2E Test Suite Summary"
echo -e "==============================================================================${NC}"
echo ""
for result in "${SUITE_RESULTS[@]}"; do
    echo -e "  $result"
done
echo ""
echo -e "  Scripts Passed: ${GREEN}$SUITE_PASSED${NC}"
echo -e "  Scripts Failed: ${RED}$SUITE_FAILED${NC}"
echo -e "  Total Scripts:  $TOTAL_SCRIPTS"
echo -e "  Duration:       ${MINUTES}m ${SECONDS}s"
echo ""

if [ "$SUITE_FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}All test suites passed!${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}Some test suites failed.${NC}"
    echo ""
    exit 1
fi
