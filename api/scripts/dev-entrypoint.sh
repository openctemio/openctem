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

    # go.work for a local sdk-go checkout mounted at /app/sdk-go, only when the
    # API actually requires sdk-go (it does since the chunked feed transfer).
    # Without that requirement, adding sdk-go to the workspace serves no
    # purpose and can only change which versions of shared dependencies the
    # dev binary is built with (MVS across the workspace), so it would no
    # longer match CI and the release image; such a go.work is removed.
    # A mounted checkout that lacks a package the API imports (an older
    # branch) would break every hot-reload build: then the go.mod pin is used.
    if [ -d "/app/sdk-go" ] && grep -q 'github.com/openctemio/sdk-go ' /app/go.mod; then
        echo "Creating go.work for local SDK..."
        cat > /app/go.work <<GOWORK
go $(grep '^go ' /app/go.mod | awk '{print $2}')

use (
	.
	./sdk-go
)
GOWORK
        if ! (cd /app && go list -deps ./cmd/server >/dev/null 2>&1); then
            echo "Warning: /app/sdk-go does not build with this API (check out sdk-go main); using the go.mod pin"
            rm -f /app/go.work /app/go.work.sum
        fi
    elif [ -f /app/go.work ] && grep -q '^[[:space:]]*\./sdk-go$' /app/go.work; then
        echo "Removing go.work: the API does not require sdk-go"
        rm -f /app/go.work /app/go.work.sum
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
