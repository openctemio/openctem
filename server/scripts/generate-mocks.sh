#!/bin/bash

# =============================================================================
# Mock Generation Script
# =============================================================================

set -e

# Check if mockgen is installed
if ! command -v mockgen &> /dev/null; then
    echo "Error: mockgen is not installed"
    echo "Install with: go install go.uber.org/mock/mockgen@latest"
    exit 1
fi

echo "Generating mocks..."

# Create mocks directory
mkdir -p internal/mocks

# Generate mocks for repositories
mockgen -source=internal/domain/asset/repository.go -destination=internal/mocks/asset_repository_mock.go -package=mocks

echo "Mocks generated successfully!"
