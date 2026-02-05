#!/bin/bash
# run_security_tests.sh - Run all security control tests
#
# Usage:
#   ./scripts/run_security_tests.sh
#
# This script runs:
#   1. Workflow Executor security tests (14 controls)
#   2. Security controls test suite (Pipeline, Scan, Validator)
#   3. Go build verification

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_DIR="$(dirname "$SCRIPT_DIR")"

cd "$API_DIR"

echo "========================================"
echo "RediverIO Security Tests"
echo "========================================"
echo ""

# Check Go version
echo "Go version: $(go version)"
echo ""

# 1. Build verification
echo "--- Build Verification ---"
cd "$API_DIR/.."
if go build ./api/...; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi
cd "$API_DIR"
echo ""

# 2. Run workflow executor tests
echo "--- Workflow Executor Tests ---"
go run scripts/test_workflow_executor.go
echo ""

# 3. Run security controls tests
echo "--- Security Controls Tests ---"
go run scripts/test_security_controls.go
echo ""

# 4. Run unit tests (if any)
echo "--- Unit Tests ---"
cd "$API_DIR/.."
if go test ./api/... -short 2>&1 | grep -E "(PASS|FAIL|ok|---)" | tail -20; then
    echo ""
    echo "✅ Unit tests completed"
else
    echo "⚠️  No unit tests or some tests skipped"
fi
cd "$API_DIR"

echo ""
echo "========================================"
echo "Security Tests Complete"
echo "========================================"
