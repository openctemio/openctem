#!/usr/bin/env bash
set -euo pipefail

# Test script for Assignment Rules feature
# Runs all related unit tests across engine, service, and entity layers.

cd "$(dirname "$0")/../.."

echo "=== Assignment Rules - Full Test Suite ==="
echo ""

PASS=0
FAIL=0

run_test() {
    local desc="$1"
    local pkg="$2"
    local pattern="$3"

    echo -n "  [$desc] "
    if output=$(go test "$pkg" -run "$pattern" -v -count=1 2>&1); then
        count=$(echo "$output" | grep -c "^\s*--- PASS:" || true)
        echo "PASS ($count tests)"
        PASS=$((PASS + count))
    else
        echo "FAIL"
        echo "$output" | grep -E "^--- FAIL:|FAIL" | head -10
        FAIL=$((FAIL + 1))
    fi
}

echo "1. Engine Tests (internal/app)"
run_test "MatchesConditions" "./internal/app/..." "TestMatchesConditions"
run_test "EvaluateRules" "./internal/app/..." "TestEvaluateRules"

echo ""
echo "2. Service Tests (tests/unit)"
run_test "CreateRule" "./tests/unit/..." "TestCreateRule"
run_test "GetRule" "./tests/unit/..." "TestGetRule"
run_test "UpdateRule" "./tests/unit/..." "TestUpdateRule"
run_test "DeleteRule" "./tests/unit/..." "TestDeleteRule"
run_test "ListRules" "./tests/unit/..." "TestListRules"
run_test "TestRule" "./tests/unit/..." "TestTestRule"

echo ""
echo "3. Entity Tests (tests/unit)"
run_test "AssignmentRule Entity" "./tests/unit/..." "TestAssignmentRule"
run_test "FindingGroupAssignment Entity" "./tests/unit/..." "TestNewFindingGroupAssignment|TestReconstituteFindingGroupAssignment"

echo ""
echo "4. Build Check"
echo -n "  [go build] "
if go build ./... 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results ==="
echo "  Tests passed: $PASS"
if [ "$FAIL" -gt 0 ]; then
    echo "  FAILURES: $FAIL"
    exit 1
else
    echo "  All tests passed!"
fi
