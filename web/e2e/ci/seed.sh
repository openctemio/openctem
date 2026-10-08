#!/usr/bin/env bash
# Seeds the e2e stack (web/e2e/ci/compose.yml) with what the Playwright specs
# need, then prints E2E_* variables (KEY=value lines) on stdout.
#
#   - an organization and its owner (bootstrap-admin), who signs in
#   - assets of two types, two sensors, a CTIS report with 15 findings
#     (enough for the findings picker to scroll), a scan with a run in
#     progress, a remediation task
#
# Requires: docker (also runs psql from PSQL_IMAGE, default postgres:17-alpine), curl, jq. Env: ADMIN_IMAGE (api/Dockerfile.admin-cli),
# E2E_OWNER_PASSWORD and E2E_DATABASE_URL (web/e2e/ci/make-env.sh),
# API (default http://127.0.0.1:8080), COMPOSE_NETWORK (default
# octe2e-ci_default).
set -euo pipefail

API=${API:-http://127.0.0.1:8080}
NETWORK=${COMPOSE_NETWORK:-octe2e-ci_default}
RUN=$(date +%s)
EMAIL="e2e-owner-$RUN@openctem-test.local"
OWNER_PASSWORD="${E2E_OWNER_PASSWORD:?set E2E_OWNER_PASSWORD (see web/e2e/ci/make-env.sh)}"
DATABASE_URL="${E2E_DATABASE_URL:?set E2E_DATABASE_URL}"
SLUG="e2e-$RUN"
WORK=$(mktemp -d)
JAR="$WORK/cookies"
trap 'rm -rf "$WORK"' EXIT

log() { echo "seed: $*" >&2; }

# call METHOD PATH [JSON] -> BODY; fails the script on a non-2xx answer.
call() {
  local method="$1" path="$2" data="${3:-}" csrf code
  csrf=$(awk '$6=="csrf_token"{v=$7} END{print v}' "$JAR" 2>/dev/null || true)
  local args=(-sS -o "$WORK/body" -w '%{http_code}' -X "$method" "$API$path" -b "$JAR" -c "$JAR"
    -H 'Content-Type: application/json')
  [[ -n "${ACCESS_TOKEN:-}" ]] && args+=(-H "Authorization: Bearer $ACCESS_TOKEN")
  [[ -n "$csrf" ]] && args+=(-H "X-CSRF-Token: $csrf")
  [[ -n "$data" ]] && args+=(-d "$data")
  code=$(curl "${args[@]}")
  BODY=$(cat "$WORK/body")
  if [[ ! "$code" =~ ^2 ]]; then
    log "$method $path -> $code: $(head -c 300 <<<"$BODY")"
    exit 1
  fi
}

log "organization and owner"
setup=$(docker run --rm --network "$NETWORK" -e SMTP_ENABLED=false "${ADMIN_IMAGE:?set ADMIN_IMAGE}" \
  -db="$DATABASE_URL" \
  -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
  -org-name="E2E Org $RUN" -org-slug="$SLUG" -org-owner-email="$EMAIL" 2>&1)
TOKEN=$(grep -o 'set-password?token=[^[:space:]]*' <<<"$setup" | head -1 | sed 's/.*token=//')
if [[ -z "$TOKEN" ]]; then
  log "bootstrap-admin printed no set-password link:"
  echo "$setup" >&2
  exit 1
fi
# A new organization requires two-factor authentication for its owners and
# admins (security.mfa_required_for_admins), so a password login answers with
# an enrollment challenge and no tenants. The specs sign in with a password,
# so the seed turns that requirement off for its organization, as for
# organizations that existed before the policy. Done in the database: nobody
# can sign in to change it before enrolling.
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb)
 WHERE slug = :'slug';
SQL
call POST /api/v1/auth/reset-password "{\"token\":\"$TOKEN\",\"new_password\":\"$OWNER_PASSWORD\"}"
call POST /api/v1/auth/login "{\"email\":\"$EMAIL\",\"password\":\"$OWNER_PASSWORD\"}"
TENANT_ID=$(jq -r --arg s "$SLUG" '(.tenants // [])[] | select(.slug==$s) | .id' <<<"$BODY")
if [[ -z "$TENANT_ID" ]]; then
  # Never print the body: a challenge carries a token.
  log "login returned no tenant $SLUG (response keys: $(jq -c 'keys' <<<"$BODY"))"
  exit 1
fi
call POST /api/v1/auth/token "{\"tenant_id\":\"$TENANT_ID\"}"
ACCESS_TOKEN=$(jq -r .access_token <<<"$BODY")

log "assets"
call POST /api/v1/assets '{"name":"e2e-web.example.com","type":"domain","criticality":"high","description":"e2e asset","tags":["e2e"]}'
call POST /api/v1/assets '{"name":"10.20.30.40","type":"ip_address","criticality":"medium"}'
# Active scans touch only assets the organization owns (RFC-036 active probe
# gate): a scope target covering the e2e domain lets the seed scan run.
call POST /api/v1/scope/targets '{"target_type":"domain","pattern":"e2e-web.example.com","description":"e2e scope"}'

log "sensors and a CTIS report"
# The seed pushes its report from a worker sensor without a command. A new
# tenant holds such reports for review (RFC-040 §5.3, mode "quarantine");
# switch to "warn" so the report is applied, as for tenants that existed
# before that policy.
call PUT /api/v1/sensors/result-policy '{"mode":"warn"}'
# A new tenant requires key-bound identity (RFC-052 D-4): sensors pair, no
# API key can be created. The seed needs bearer keys (it pushes with curl),
# so it allows them, as for tenants that existed before that policy.
call PUT /api/v1/sensors/identity-policy '{"bearer_keys_allowed":true}'
call POST /api/v1/sensors '{"name":"e2e-sensor","type":"worker","execution_mode":"daemon","tools":["nuclei"],"capabilities":["vulnerability"]}'
KEY=$(jq -r .api_key <<<"$BODY")
SENSOR_ID=$(jq -r .sensor.id <<<"$BODY")
# A new sensor starts at trust level New (RFC-052 §5: passive work only, no
# results without a job). The seed pushes its report without a job, so it
# promotes the sensor and allows push ingest, as an administrator would.
call GET "/api/v1/sensors/$SENSOR_ID/grant"
GRANT=$(jq -c '.trust_level = "trusted" | .allow_push_ingest = true
  | del(.sensor_id, .legacy_broad, .updated_at, .effective, .profile)' <<<"$BODY")
call PUT "/api/v1/sensors/$SENSOR_ID/grant" "$GRANT"
call POST /api/v1/sensors '{"name":"e2e-sensor-b","type":"worker","execution_mode":"daemon","tools":["nuclei"],"capabilities":["vulnerability"]}'

# A heartbeat brings e2e-sensor online and reports nuclei as installed. Ingest
# accepts a report only from a tool the sensor has reported (sensors.tools was
# dropped, #1254), and dispatch counts only reported tools too (#824). Nothing
# claims the scan's job below, so its run stays in progress for
# 10-scan-detail-runs.
code=$(curl -sS -o "$WORK/body" -w '%{http_code}' -X POST "$API/api/v2/sensor/heartbeat" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"status":"online","scanners":["nuclei"],"tools":[{"name":"nuclei","kind":"scanner","installed":true}]}')
[[ "$code" =~ ^2 ]] || { log "heartbeat -> $code: $(head -c 300 "$WORK/body")"; exit 1; }

findings=$(for i in $(seq 1 15); do
  printf '{"type":"vulnerability","title":"E2E finding %02d","severity":"%s","rule_id":"e2e-%02d","asset_ref":"a%d","description":"e2e"}\n' \
    "$i" "$([[ $((i % 3)) == 0 ]] && echo critical || echo medium)" "$i" "$((i % 2 + 1))"
done | jq -s .)
# Protocol v1 is gone: the report goes to the v2 results resource (one PUT
# is a whole report), its id a lower-case UUID that metadata.id repeats.
REPORT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr 'A-Z' 'a-z')
jq -n --arg id "$REPORT_ID" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson findings "$findings" '{
  version: "1.0",
  metadata: { id: $id, timestamp: $ts, source_type: "scanner" },
  tool: { name: "nuclei", version: "3.3.0" },
  assets: [
    { id: "a1", type: "domain", value: "e2e-web.example.com" },
    { id: "a2", type: "domain", value: "e2e-api.example.com" }
  ],
  findings: $findings
}' >"$WORK/report.json"
DIGEST=$(openssl dgst -sha256 -binary "$WORK/report.json" | base64)
code=$(curl -sS -o "$WORK/body" -w '%{http_code}' -X PUT "$API/api/v2/sensor/results/$REPORT_ID" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/vnd.openctem.ctis.v1+json' \
  -H "Content-Digest: sha-256=:$DIGEST:" --data-binary @"$WORK/report.json")
[[ "$code" =~ ^2 ]] || { log "ingest -> $code: $(head -c 300 "$WORK/body")"; exit 1; }

log "a scan with a run in progress"
call POST /api/v1/scans/ '{"name":"E2E scan","scan_type":"single","scanner_name":"nuclei","targets":["e2e-web.example.com"],"schedule_type":"manual"}'
call POST "/api/v1/scans/$(jq -r .id <<<"$BODY")/trigger" '{}'

log "remediation task"
call POST /api/v1/remediation/campaigns '{"name":"E2E remediation task","description":"e2e","priority":"high"}'

# Ingest is asynchronous: wait until the findings are listed.
for _ in $(seq 1 30); do
  call GET "/api/v1/findings?per_page=50"
  n=$(jq -r '[.data[]? | select(.title|startswith("E2E finding"))] | length' <<<"$BODY")
  [[ "$n" -ge 15 ]] && break
  sleep 1
done
[[ "$n" -ge 15 ]] || { log "only $n of 15 findings visible"; exit 1; }

log "a member (E2E_LIMITED_*)"
# The member-or-viewer checks in 09, 11 and 12 skip without one.
MEMBER_EMAIL="e2e-member-$RUN@openctem-test.local"
MEMBER_PASSWORD="$(openssl rand -hex 10)Q$(openssl rand -hex 3)"
call GET /api/v1/roles
ROLE_ID=$(jq -r '[(.roles // .data // .)[] | select((.slug // .name | ascii_downcase) == "member")][0].id' <<<"$BODY")
[[ -n "$ROLE_ID" && "$ROLE_ID" != null ]] || { log "no member role"; exit 1; }
call POST "/api/v1/tenants/$SLUG/invitations" "{\"email\":\"$MEMBER_EMAIL\",\"role_ids\":[\"$ROLE_ID\"]}"
INVITE_TOKEN=$(jq -r .token <<<"$BODY")

# The specs sign in through the form; end this API session.
call POST /api/v1/auth/logout '{}'

ACCESS_TOKEN=
JAR="$WORK/member-cookies"
call POST /api/v1/auth/register "{\"email\":\"$MEMBER_EMAIL\",\"password\":\"$MEMBER_PASSWORD\",\"name\":\"E2E Member\"}"
call POST /api/v1/auth/login "{\"email\":\"$MEMBER_EMAIL\",\"password\":\"$MEMBER_PASSWORD\"}"
call POST /api/v1/invitations/accept-with-refresh "{\"token\":\"$INVITE_TOKEN\",\"refresh_token\":\"$(jq -r '.refresh_token // empty' <<<"$BODY")\"}"
call POST /api/v1/auth/logout '{}'

log "done"
echo "E2E_USER_EMAIL=$EMAIL"
echo "E2E_USER_PASSWORD=$OWNER_PASSWORD"
echo "E2E_TENANT_SLUG=$SLUG"
echo "E2E_LIMITED_EMAIL=$MEMBER_EMAIL"
echo "E2E_LIMITED_PASSWORD=$MEMBER_PASSWORD"
