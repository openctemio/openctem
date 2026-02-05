#!/bin/bash
# =============================================================================
# Development Admin Setup Script
# =============================================================================
#
# Creates an admin user for local development.
#
# Usage:
#   ./scripts/dev-setup-admin.sh
#   ./scripts/dev-setup-admin.sh admin@example.com ops_admin
#   DB_URL=postgres://... ./scripts/dev-setup-admin.sh
#
# Environment variables:
#   DB_URL       - Database connection string (default: postgres://exploop:exploop@localhost:5432/exploop?sslmode=disable)
#   ADMIN_EMAIL  - Admin email (default: admin@localhost)
#   ADMIN_ROLE   - Admin role: super_admin, ops_admin, viewer (default: super_admin)
#   ADMIN_NAME   - Admin name (default: derived from email)
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DB_URL="${DB_URL:-postgres://exploop:exploop@localhost:5432/exploop?sslmode=disable}"
ADMIN_EMAIL="${1:-${ADMIN_EMAIL:-admin@localhost}}"
ADMIN_ROLE="${2:-${ADMIN_ROLE:-super_admin}}"
ADMIN_NAME="${ADMIN_NAME:-}"

# Determine script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
API_DIR="$PROJECT_ROOT/api"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Rediver Admin Setup (Development)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if api directory exists
if [ ! -d "$API_DIR" ]; then
    echo -e "${RED}Error: API directory not found at $API_DIR${NC}"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed. Please install Go first.${NC}"
    exit 1
fi

# Build bootstrap-admin
echo -e "${YELLOW}Building bootstrap-admin...${NC}"
cd "$API_DIR"

# Check if go.work is empty (causes issues)
if [ -f "go.work" ] && [ ! -s "go.work" ]; then
    echo -e "${YELLOW}Note: Empty go.work detected, using GOWORK=off${NC}"
    export GOWORK=off
fi

mkdir -p ./bin
go build -o ./bin/bootstrap-admin ./cmd/bootstrap-admin
echo -e "${GREEN}Build successful!${NC}"
echo ""

# Run bootstrap-admin
echo -e "${YELLOW}Creating admin user...${NC}"
echo -e "  Email: ${ADMIN_EMAIL}"
echo -e "  Role:  ${ADMIN_ROLE}"
echo ""

CMD="./bin/bootstrap-admin -db \"$DB_URL\" -email \"$ADMIN_EMAIL\" -role \"$ADMIN_ROLE\""
if [ -n "$ADMIN_NAME" ]; then
    CMD="$CMD -name \"$ADMIN_NAME\""
fi

eval $CMD

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo ""
echo "1. Save the API key shown above (it won't be shown again)"
echo ""
echo "2. To use with Admin UI:"
echo "   - Open http://localhost:3001"
echo "   - Enter the API key in the login form"
echo ""
echo "3. To use with curl:"
echo "   export ADMIN_API_KEY='exp-admin-...'"
echo "   curl -H 'X-Admin-API-Key: \$ADMIN_API_KEY' \\"
echo "     http://localhost:8080/api/v1/admin/auth/validate"
echo ""
echo "4. To use with Admin CLI:"
echo "   export REDIVER_API_URL=http://localhost:8080"
echo "   export EXPLOOP_API_KEY='exp-admin-...'"
echo "   exploop-admin get agents"
echo ""
