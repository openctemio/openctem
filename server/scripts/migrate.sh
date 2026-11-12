#!/bin/bash

# =============================================================================
# Database Migration Script
# =============================================================================

set -e

# Load environment variables
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
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
DB_USER=${DB_USER:-openctem}
# DB_PASSWORD is required, no default
DB_NAME=${DB_NAME:-openctem}
DB_SSLMODE=${DB_SSLMODE:-disable}
MIGRATIONS_DIR=${MIGRATIONS_DIR:-migrations}

# Percent-encodes one URL part (user or password): a value with @ : / ? # or %
# in it otherwise breaks the URL or changes what it means.
urlenc() (
  LC_ALL=C
  s=$1
  while [ -n "$s" ]; do
    rest=${s#?}
    c=${s%"$rest"}
    s=$rest
    case $c in
      [A-Za-z0-9._~-]) printf '%s' "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
)

# Connection string without the password: it goes in PGPASSWORD, which the
# runner's driver reads, so it never shows in the process list.
DATABASE_URL="postgres://$(urlenc "${DB_USER}")@${DB_HOST}:${DB_PORT}/$(urlenc "${DB_NAME}")?sslmode=${DB_SSLMODE}"
export PGPASSWORD="${DB_PASSWORD}"

# The migration runner: an installed openctem-migrate, else this tree's.
migrate() {
    if command -v openctem-migrate > /dev/null 2>&1; then
        openctem-migrate "$@"
    elif command -v go > /dev/null 2>&1; then
        GOWORK=off go run ./cmd/openctem-migrate "$@"
    else
        echo "Error: neither openctem-migrate nor go is installed (build it: go build -o bin/openctem-migrate ./cmd/openctem-migrate)"
        exit 1
    fi
}

# Parse command
COMMAND=${1:-up}

case $COMMAND in
    up)
        echo "Running migrations up..."
        migrate -path "${MIGRATIONS_DIR}" -database "${DATABASE_URL}" up
        ;;
    down)
        echo "Rolling back the most recently applied migration..."
        migrate -path "${MIGRATIONS_DIR}" -database "${DATABASE_URL}" down "${2:-1}"
        ;;
    down-all)
        if [ "${2:-}" != "--yes" ]; then
            echo "Error: down-all drops every table; rerun with: $0 down-all --yes"
            exit 1
        fi
        echo "Rolling back all migrations..."
        migrate -path "${MIGRATIONS_DIR}" -database "${DATABASE_URL}" down 2147483647
        ;;
    force)
        VERSION=${2:?usage: $0 force VERSION (or -1 to only clear the dirty flag)}
        echo "Clearing the dirty flag and recording ${VERSION} as applied..."
        migrate -path "${MIGRATIONS_DIR}" -database "${DATABASE_URL}" force "${VERSION}"
        ;;
    version|status)
        migrate -path "${MIGRATIONS_DIR}" -database "${DATABASE_URL}" "${COMMAND}"
        ;;
    create)
        bash scripts/migration-number.sh new "${2:?usage: $0 create snake_case_name}"
        ;;
    *)
        echo "Usage: $0 {up|down [N]|down-all --yes|force V|version|status|create NAME}"
        echo ""
        echo "Commands:"
        echo "  up             - Apply every migration the database has not applied"
        echo "  down [N]       - Roll back the N (default 1) most recently applied migrations"
        echo "  down-all --yes - Roll back all migrations (destructive, needs --yes)"
        echo "  force V        - Clear the dirty flag and record V as applied (-1: only clear the flag)"
        echo "  version        - Show the highest applied version"
        echo "  status         - Show the pending migrations"
        echo "  create NAME    - Create a migration with a timestamp version"
        exit 1
        ;;
esac

echo "Done!"
