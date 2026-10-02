#!/bin/sh
# =============================================================================
# Development Entrypoint Script
# =============================================================================
# This script runs migrations before starting the development server.
#
# Features:
#   - Waits for database to be ready
#   - Runs migrations automatically
#   - Starts Air for hot reload
# =============================================================================

set -e

echo "=== Development Entrypoint ==="

# Wait for database to be ready
wait_for_db() {
    echo "Waiting for database..."
    max_retries=30
    retries=0

    while [ $retries -lt $max_retries ]; do
        if pg_isready -h "${DB_HOST:-postgres}" -p "${DB_PORT:-5432}" -U "${DB_USER:-openctem}" > /dev/null 2>&1; then
            echo "Database is ready!"
            return 0
        fi
        retries=$((retries + 1))
        echo "Waiting for database... ($retries/$max_retries)"
        sleep 1
    done

    echo "Database not ready after $max_retries attempts"
    return 1
}

# Run migrations
run_migrations() {
    echo "Running database migrations..."

    # Build database URL
    DB_URL="postgres://${DB_USER:-openctem}:${DB_PASSWORD:-secret}@${DB_HOST:-postgres}:${DB_PORT:-5432}/${DB_NAME:-openctem}?sslmode=${DB_SSLMODE:-disable}"

    # Check if migrate command exists
    if command -v migrate > /dev/null 2>&1; then
        migrate -path /app/migrations -database "$DB_URL" up || {
            echo "Warning: Migration failed or no new migrations"
        }
        echo "Migrations complete!"
    else
        echo "Warning: migrate not installed, skipping migrations"
    fi
}

# Main
main() {
    # Clean old binary to ensure fresh build
    rm -rf /app/tmp/openctem 2>/dev/null || true

    # Create go.work for local SDK development
    if [ -d "/app/sdk-go" ]; then
        echo "Creating go.work for local SDK..."
        cat > /app/go.work <<GOWORK
go $(grep '^go ' /app/go.mod | awk '{print $2}')

use (
	.
	./sdk-go
)
GOWORK
    fi

    # Ensure go dependencies are in sync
    echo "Syncing Go dependencies..."
    go mod download 2>/dev/null || go mod tidy 2>/dev/null || true

    # Wait for database
    wait_for_db

    # Run migrations if AUTO_MIGRATE is enabled (default: true for dev)
    if [ "${AUTO_MIGRATE:-true}" = "true" ]; then
        run_migrations
    else
        echo "Skipping migrations (AUTO_MIGRATE=false)"
    fi

    # Start the application with Air
    echo "Starting development server with Air..."
    exec air -c .air.toml
}

main "$@"
