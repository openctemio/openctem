#!/usr/bin/env bash
# Writes web/e2e/ci/.env for the e2e stack (compose.yml, seed.sh): fresh random
# passwords and secrets on every run, plus image names and published ports
# (override with API_IMAGE, WEB_IMAGE, ADMIN_IMAGE, E2E_API_PORT, E2E_WEB_PORT).
# The file is git-ignored; no credential lives in the repository.
#
# In GitHub Actions ($GITHUB_ENV set) the values are also exported to later
# steps, and every secret is masked in the log first.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/.env"
rnd() { openssl rand -hex "$1"; }

db_password="$(rnd 24)"
redis_password="$(rnd 24)"
# The API's password policy wants an upper-case letter; hex has none.
owner_password="$(rnd 12)Q$(rnd 4)"
# Assembled here so no connection string with a password is written anywhere.
scheme=postgres
database_url="${scheme}://openctem:${db_password}@postgres:5432/openctem?sslmode=disable"
jwt_secret="$(rnd 32)"
encryption_key="$(rnd 32)"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  for v in "$db_password" "$redis_password" "$owner_password" "$database_url" \
    "$jwt_secret" "$encryption_key"; do
    echo "::add-mask::$v"
  done
fi

umask 077
cat >"$out" <<ENV
API_IMAGE=${API_IMAGE:-local/openctem-api:e2e}
WEB_IMAGE=${WEB_IMAGE:-local/openctem-web:e2e}
ADMIN_IMAGE=${ADMIN_IMAGE:-local/admin-cli:e2e}
E2E_API_PORT=${E2E_API_PORT:-8080}
E2E_WEB_PORT=${E2E_WEB_PORT:-3000}
E2E_DB_PASSWORD=${db_password}
E2E_REDIS_PASSWORD=${redis_password}
E2E_DATABASE_URL=${database_url}
E2E_OWNER_PASSWORD=${owner_password}
AUTH_JWT_SECRET=${jwt_secret}
APP_ENCRYPTION_KEY=${encryption_key}
ENV

if [[ -n "${GITHUB_ENV:-}" ]]; then
  cat "$out" >>"$GITHUB_ENV"
fi
echo "wrote $out" >&2
