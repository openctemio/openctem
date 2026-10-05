#!/usr/bin/env bash
# Protocol-v1 compatibility check (RFC-023 §9.2, C8).
#
# Proves that a sensor built with the LAST RELEASED sdk-go keeps working
# against this API build: connection test, heartbeat, CTIS push, command
# lifecycle, suppressions, key renewal. The sensor side lives in
# tests/compat/v1 (its own module, pinned to that SDK release); this script
# prepares a tenant, a sensor key and a queued command, runs it, and checks
# the platform recorded the outcome.
#
# The provisioning calls below use the MANAGEMENT API, which is allowed to
# change between versions; update them with it. The protocol-v1 surface the
# harness exercises is frozen and must never need changes here.
#
# Requires: a migrated database, the API running at COMPAT_API_URL, curl, jq,
# and the bootstrap-admin binary (it creates the organization the way a first
# install does). Usage:
#   COMPAT_API_URL=http://127.0.0.1:8080 DATABASE_URL=postgres://... \
#   BOOTSTRAP_ADMIN_BIN=./bin/bootstrap-admin scripts/compat-v1.sh
set -euo pipefail

API="${COMPAT_API_URL:?COMPAT_API_URL is required}"
: "${DATABASE_URL:?DATABASE_URL is required}"
BOOTSTRAP_ADMIN_BIN="${BOOTSTRAP_ADMIN_BIN:?BOOTSTRAP_ADMIN_BIN is required}"
HARNESS_DIR="$(cd "$(dirname "$0")/../tests/compat/v1" && pwd)"

RUN="$(date +%s)-$$"
EMAIL="compat-owner-$RUN@openctem-test.local"
PASSWORD="CompatP@ss123!"
SLUG="compat-v1-$RUN"
WORK="$(mktemp -d)"
JAR="$WORK/cookies"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "[FAIL] $*" >&2; exit 1; }

# call METHOD PATH [JSON] — authenticated management call; prints the body,
# fails on a non-2xx status.
call() {
	local method="$1" path="$2" data="${3:-}" csrf code
	csrf=$(awk '$6=="csrf_token"{v=$7} END{print v}' "$JAR" 2>/dev/null || true)
	local args=(-sS -o "$WORK/body" -w '%{http_code}' -X "$method" "$API$path"
		-b "$JAR" -c "$JAR" -H 'Content-Type: application/json')
	[ -n "${ACCESS_TOKEN:-}" ] && args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
	[ -n "$csrf" ] && args+=(-H "X-CSRF-Token: $csrf")
	[ -n "$data" ] && args+=(-d "$data")
	code=$(curl "${args[@]}")
	[[ "$code" =~ ^2 ]] || fail "$method $path -> HTTP $code: $(head -c 300 "$WORK/body")"
	cat "$WORK/body"
}

echo "== provisioning (management API)"
# A platform administrator plus the organization and its owner, as at first
# install. Without SMTP the owner's one-time set-password link is printed;
# the owner sets a password through it like a person would.
# SMTP_ENABLED=false keeps the link on stdout even where SMTP is configured.
setup=$(SMTP_ENABLED=false "$BOOTSTRAP_ADMIN_BIN" -db="$DATABASE_URL" \
	-email="compat-admin-$RUN@openctem-test.local" -no-backup \
	-org-name="Compat V1" -org-slug="$SLUG" -org-owner-email="$EMAIL")
SETUP_TOKEN=$(grep -o 'set-password?token=[^[:space:]]*' <<<"$setup" | head -1 | sed 's/.*token=//')
[ -n "$SETUP_TOKEN" ] || fail "bootstrap-admin printed no set-password link"
call POST /api/v1/auth/reset-password "{\"token\":\"$SETUP_TOKEN\",\"new_password\":\"$PASSWORD\"}" >/dev/null

TENANT_ID=$(call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" |
	jq -r --arg s "$SLUG" '.tenants[] | select(.slug==$s) | .id')
[ -n "$TENANT_ID" ] || fail "tenant $SLUG not in login response"
ACCESS_TOKEN=$(call POST /api/v1/auth/token "{\"tenant_id\":\"$TENANT_ID\"}" | jq -r '.access_token')

# The harness pushes a report outside any command, as sensors on old SDKs do.
# A new tenant holds such reports from a worker sensor for review
# (RFC-040 §5.3, mode "quarantine"); tenants that existed before that policy
# are on "warn", which is the case this check is about.
call PUT /api/v1/sensors/result-policy '{"mode":"warn"}' >/dev/null
# Protocol v1 sensors use bearer keys. A new tenant requires key-bound
# identity (RFC-052 D-4); tenants that existed before that policy allow
# bearer keys, which is the case this check is about.
call PUT /api/v1/sensors/identity-policy '{"bearer_keys_allowed":true}' >/dev/null

created=$(call POST /api/v1/sensors \
	'{"name":"compat-v1","type":"worker","execution_mode":"daemon","tools":["nuclei"],"capabilities":["vulnerability"]}')
SENSOR_ID=$(jq -r '.sensor.id' <<<"$created")
API_KEY=$(jq -r '.api_key' <<<"$created")
[ -n "$API_KEY" ] && [ "$API_KEY" != null ] || fail "sensor created without an API key"

COMMAND_ID=$(call POST /api/v1/commands "{\"sensor_id\":\"$SENSOR_ID\",\"type\":\"health_check\"}" | jq -r '.id')
[ -n "$COMMAND_ID" ] && [ "$COMMAND_ID" != null ] || fail "command not created"
echo "tenant=$TENANT_ID sensor=$SENSOR_ID command=$COMMAND_ID"

echo "== protocol v1, driven by the last released sdk-go"
# The SDK's API client refuses loopback by default; the API under test runs on it.
(cd "$HARNESS_DIR" && GOWORK=off \
	OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK=1 \
	COMPAT_API_URL="$API" COMPAT_AGENT_ID="$SENSOR_ID" COMPAT_API_KEY="$API_KEY" \
	COMPAT_COMMAND_ID="$COMMAND_ID" go run .)

echo "== the platform recorded the outcome"
status=$(call GET "/api/v1/commands/$COMMAND_ID" | jq -r '.status')
[ "$status" = completed ] || fail "command status is '$status', want completed"
echo "[PASS] command recorded as completed"

health=$(call GET "/api/v1/sensors/$SENSOR_ID" | jq -r '.health')
[ "$health" = online ] || fail "sensor health is '$health', want online"
echo "[PASS] sensor shown online"

echo "PASS: protocol v1 is compatible"
