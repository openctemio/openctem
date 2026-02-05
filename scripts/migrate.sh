#!/bin/bash

# =============================================================================
# Database Migration Script
# =============================================================================

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# SECURITY: Fail if DB_PASSWORD not set (no default password)
if [ -z "${DB_PASSWORD}" ]; then
    echo "Error: DB_PASSWORD environment variable is required"
    echo "Set it in .env file or export DB_PASSWORD=your_password"
    exit 1
fi

# Default values (no default password for security)
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-exploop}
# DB_PASSWORD is required, no default
DB_NAME=${DB_NAME:-exploop}
DB_SSLMODE=${DB_SSLMODE:-disable}
MIGRATIONS_DIR=${MIGRATIONS_DIR:-migrations}

# Build connection string
DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSLMODE}"

# Check if migrate is installed
if ! command -v migrate &> /dev/null; then
    echo "Error: migrate is not installed"
    echo "Install with: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
    exit 1
fi

# Parse command
COMMAND=${1:-up}

case $COMMAND in
    up)
        echo "Running migrations up..."
        migrate -path ${MIGRATIONS_DIR} -database "${DATABASE_URL}" up
        ;;
    down)
        echo "Running migrations down..."
        migrate -path ${MIGRATIONS_DIR} -database "${DATABASE_URL}" down 1
        ;;
    down-all)
        echo "Rolling back all migrations..."
        migrate -path ${MIGRATIONS_DIR} -database "${DATABASE_URL}" down -all
        ;;
    force)
        VERSION=${2:-0}
        echo "Forcing version to ${VERSION}..."
        migrate -path ${MIGRATIONS_DIR} -database "${DATABASE_URL}" force ${VERSION}
        ;;
    version)
        echo "Current migration version:"
        migrate -path ${MIGRATIONS_DIR} -database "${DATABASE_URL}" version
        ;;
    create)
        NAME=${2:-unnamed}
        echo "Creating migration: ${NAME}"
        migrate create -ext sql -dir ${MIGRATIONS_DIR} -seq ${NAME}
        ;;
    *)
        echo "Usage: $0 {up|down|down-all|force|version|create} [args]"
        echo ""
        echo "Commands:"
        echo "  up         - Run all pending migrations"
        echo "  down       - Rollback last migration"
        echo "  down-all   - Rollback all migrations"
        echo "  force N    - Force set version to N"
        echo "  version    - Show current version"
        echo "  create N   - Create new migration with name N"
        exit 1
        ;;
esac

echo "Done!"
