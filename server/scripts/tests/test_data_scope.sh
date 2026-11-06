#!/bin/bash
# Test script for Layer 2 Data Scope implementation
# Runs all data scope related tests and the full unit test suite

set -e

echo "=== Data Scope Unit Tests ==="
echo ""

echo "1. Running data scope tests..."
go test -v -run "TestGetAssetWithScope|TestListAssets|TestGetFindingWithScope|TestGetFindingStats|TestAssetFilter|TestFindingFilter_WithDataScope" ./tests/unit/
echo ""

echo "2. Running full unit test suite..."
go test -v -count=1 ./tests/unit/
echo ""

echo "3. Running go vet..."
go vet ./...
echo ""

echo "4. Running go build..."
go build ./...
echo ""

echo "=== All tests passed ==="
