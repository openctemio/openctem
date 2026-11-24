#!/usr/bin/env bash
# Extra rows for the layout matrix (layout-matrix.sh, .github/workflows/
# layout-matrix.yml), added after seed.sh so the settings lists are seen with
# data:
#   - 4 API keys (varied scopes, expiry, one revoked); key_hash is a digest of a
#     fixed label and key_prefix a made-up prefix: no usable key exists
#   - 3 SLA policies (default, a strict one, an inactive one)
#   - 3 notification channels (Slack, Teams, a webhook in an error state)
#   - one row behind each detail page the matrix opens by id: SBOM components,
#     a CTEM cycle, an asset group, a pentest campaign in testing with a
#     finding, an own pentest template, an own scan workflow (a copy of a
#     built-in one), an import mapping, a bug bounty program (through the API,
#     as the owner); an emerging-threat alert, a Jira ticket mapping draft and
#     a pending AI-application confirmation (SQL: no API writes them)
#   - the legal pages turned on (platform setting "legal": they answer 404
#     while it is off)
# The invitation link (/invitations/[token]) and the account of two
# organizations (/select-tenant) come from seed.sh (E2E_INVITEE_*, E2E_SWITCH_*).
# Fixture data only: example.com names and RFC 5737 addresses.
#
# Prints E2E_MCP_CONFIRM_ID=<id> on stdout (the pending confirmation that
# /mcp/confirm/[id] opens): append it to the seed output.
#
# Requires: docker (runs psql from PSQL_IMAGE, default postgres:17-alpine),
# curl and jq.
# Env: E2E_DATABASE_URL (make-env.sh), E2E_TENANT_SLUG, E2E_USER_EMAIL and
# E2E_USER_PASSWORD (seed.sh output), API (the API base URL, default
# http://127.0.0.1:8080), COMPOSE_NETWORK (default octe2e-ci_default).
set -euo pipefail
DATABASE_URL="${E2E_DATABASE_URL:?set E2E_DATABASE_URL}"
SLUG="${E2E_TENANT_SLUG:?set E2E_TENANT_SLUG (seed.sh output)}"
EMAIL="${E2E_USER_EMAIL:?set E2E_USER_EMAIL (seed.sh output)}"
PASS="${E2E_USER_PASSWORD:?set E2E_USER_PASSWORD (seed.sh output)}"
API="${API:-http://127.0.0.1:8080}"
NETWORK="${COMPOSE_NETWORK:-octe2e-ci_default}"
psql_() {
  docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG" -v email="$EMAIL" "$@"
}

psql_ >/dev/null <<'SQL'
SELECT id AS tid FROM tenants WHERE slug = :'slug' \gset
SELECT id AS uid FROM users WHERE email = :'email' \gset

INSERT INTO api_keys (tenant_id, user_id, created_by, name, description, key_hash, key_prefix, scopes,
                      status, expires_at, last_used_at, last_used_ip, use_count, revoked_at, revoked_by)
VALUES
 (:'tid', :'uid', :'uid', 'CI pipeline (read findings)', 'Used by the build pipeline to read open findings',
  encode(sha256('seed-ci'::bytea), 'hex'), 'oc_ci7f', '{findings:read,assets:read}', 'active',
  now() + interval '80 days', now() - interval '2 hours', '192.0.2.10', 1834, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Findings feed for the SIEM', 'Pulls findings into the SIEM every 15 minutes',
  encode(sha256('seed-siem'::bytea), 'hex'), 'oc_s13m', '{findings:read}', 'active',
  now() + interval '6 days', now() - interval '9 minutes', '198.51.100.24', 52011, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Asset import from CMDB (cmdb.example.com)', NULL,
  encode(sha256('seed-cmdb'::bytea), 'hex'), 'oc_cmdb', '{assets:read,assets:write,scans:read,findings:read}', 'active',
  NULL, NULL, NULL, 0, NULL, NULL),
 (:'tid', :'uid', :'uid', 'Old ticket sync', 'Replaced by the Jira integration',
  encode(sha256('seed-old'::bytea), 'hex'), 'oc_o1d0', '{findings:read,findings:write}', 'revoked',
  now() - interval '20 days', now() - interval '40 days', '203.0.113.7', 310, now() - interval '30 days', :'uid');

INSERT INTO sla_policies (tenant_id, name, description, is_default, critical_days, high_days, medium_days,
                          low_days, info_days, warning_threshold_percent, is_active)
SELECT :'tid', 'Standard remediation', 'Default windows for every asset', true, 7, 30, 60, 90, 180, 75, true
WHERE NOT EXISTS (SELECT 1 FROM sla_policies WHERE tenant_id = :'tid' AND is_default AND asset_id IS NULL AND practice IS NULL);
INSERT INTO sla_policies (tenant_id, name, description, is_default, critical_days, high_days, medium_days,
                          low_days, info_days, warning_threshold_percent, is_active)
VALUES
 (:'tid', 'Internet-facing production (strict)', 'Shorter windows for public services on example.com', false, 2, 7, 21, 45, 90, 60, true),
 (:'tid', 'Lab and test hosts', NULL, false, 30, 60, 120, 180, 365, 80, false);

WITH ch AS (
  INSERT INTO integrations (tenant_id, name, description, category, provider, status, status_message,
                            auth_type, base_url, last_sync_at, config, created_by)
  VALUES
   (:'tid', 'Security alerts (#sec-alerts)', 'Critical and high findings', 'notification', 'slack', 'connected', NULL,
    'token', NULL, now() - interval '1 hour', '{}', :'uid'),
   (:'tid', 'SOC on-call (Teams)', NULL, 'notification', 'teams', 'connected', NULL,
    'token', NULL, now() - interval '3 hours', '{}', :'uid'),
   (:'tid', 'Ticket intake webhook', 'Posts new exposures to hooks.example.com', 'notification', 'webhook', 'error',
    'POST https://hooks.example.com/intake answered 502 Bad Gateway', 'token', 'https://hooks.example.com/intake',
    now() - interval '2 days', '{}', :'uid')
  RETURNING id, provider)
INSERT INTO integration_notification_extensions (integration_id, enabled_severities, enabled_event_types)
SELECT id,
       CASE provider WHEN 'teams' THEN '["critical","high","medium","low","info"]'::jsonb ELSE '["critical","high"]'::jsonb END,
       '["security_alert","new_finding","new_exposure"]'::jsonb
FROM ch;
SQL

# Detail rows through the API, as the owner (one session; bearer token).
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
XFF="198.18.$((RANDOM % 200)).$((RANDOM % 250 + 1))"
api() { # api METHOD PATH [JSON|@file] -> body on stdout, fails on non-2xx
  local code; code=$(curl -sS -o "$W/b" -w '%{http_code}' -X "$1" "$API$2" -H "X-Forwarded-For: $XFF" \
    -H 'Content-Type: application/json' ${TOKEN:+-H "Authorization: Bearer $TOKEN"} ${3:+--data-binary "$3"})
  [[ "$code" =~ ^2 ]] || { echo "seed-matrix: $1 $2 -> $code $(head -c 300 "$W/b")" >&2; return 1; }
  cat "$W/b"
}
TOKEN=
LOGIN=$(curl -sS -c "$W/jar" -b "$W/jar" -H "X-Forwarded-For: $XFF" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg e "$EMAIL" --arg p "$PASS" '{email:$e,password:$p}')" "$API/api/v1/auth/login")
TID=$(jq -r --arg s "$SLUG" '[(.tenants // [])[] | select(.slug==$s)][0].id' <<<"$LOGIN")
CSRF=$(awk '$6=="csrf_token"{v=$7} END{print v}' "$W/jar")
TOKEN=$(curl -sS -c "$W/jar" -b "$W/jar" -H "X-Forwarded-For: $XFF" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -d "{\"tenant_id\":\"$TID\"}" "$API/api/v1/auth/token" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || { echo "seed-matrix: owner sign-in failed" >&2; exit 1; }
ASSET=$(api GET "/api/v1/assets?per_page=50" | jq -r '[.data[] | select(.name=="e2e-web.example.com")][0].id')

cat >"$W/sbom.json" <<'J'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
 "metadata":{"component":{"type":"application","name":"shop-frontend","version":"3.4.0"}},
 "components":[
  {"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","licenses":[{"license":{"id":"MIT"}}]},
  {"type":"library","group":"org.apache.logging.log4j","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1","licenses":[{"license":{"id":"Apache-2.0"}}]},
  {"type":"library","name":"requests","version":"2.25.0","purl":"pkg:pypi/requests@2.25.0","licenses":[{"license":{"id":"Apache-2.0"}}]}]}
J
api POST "/api/v1/components/import?asset_id=$ASSET" "@$W/sbom.json" >/dev/null
api POST /api/v1/ctem-cycles/ '{"name":"Q1 2099 external exposure review","description":"Internet-facing services on example.com","start_date":"2099-01-01","end_date":"2099-03-31","charter":{}}' >/dev/null
api POST /api/v1/asset-groups/ "{\"name\":\"Public web (example.com)\",\"description\":\"Internet-facing web services\",\"environment\":\"production\",\"criticality\":\"high\",\"owner\":\"Web platform team\",\"owner_email\":\"web-team@example.com\",\"tags\":[\"public\"],\"existing_asset_ids\":[\"$ASSET\"]}" >/dev/null
CAMP=$(api POST /api/v1/pentest/campaigns/ "{\"name\":\"Web application test, shop.example.com\",\"description\":\"Grey-box test of the shop\",\"methodology\":\"OWASP WSTG\",\"client_name\":\"Example Shop\",\"start_date\":\"2099-01-05\",\"end_date\":\"2099-01-30\",\"objectives\":[\"Find authorization flaws\"],\"asset_ids\":[\"$ASSET\"],\"approach\":\"grey_box\",\"environment\":\"staging\",\"tlp\":\"amber\"}" | jq -r .id)
api PATCH "/api/v1/pentest/campaigns/$CAMP/status" '{"status":"in_progress"}' >/dev/null
api POST "/api/v1/pentest/campaigns/$CAMP/findings" "{\"title\":\"Order history readable by another customer (IDOR)\",\"description\":\"The order endpoint returns any order by its number.\",\"asset_id\":\"$ASSET\",\"severity\":\"high\",\"status\":\"draft\",\"cvss_score\":7.5,\"cvss_vector\":\"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N\",\"cvss_version\":\"3.1\",\"cwe_id\":\"CWE-639\",\"owasp_category\":\"A01:2021\",\"steps_to_reproduce\":[\"Sign in as customer A\",\"Open /api/orders/1001, an order of customer B\"],\"business_impact\":\"Customers can read each other's orders.\",\"remediation_guidance\":\"Check the order owner on every request.\",\"affected_assets\":[\"https://shop.example.com/api/orders\"],\"tags\":[\"idor\"]}" >/dev/null
api POST /api/v1/pentest/templates/ '{"name":"Order lookup without ownership check","category":"authorization","severity":"high","owasp_category":"A01:2021","cwe_id":"CWE-639","description":"An order is returned to any signed-in customer who knows its number.","steps_to_reproduce":["Sign in as one customer","Request an order of another customer"],"business_impact":"Order data of other customers is exposed.","remediation":"Check the owner of the order on every request.","tags":["idor"]}' >/dev/null
SYSWF=$(api GET "/api/v1/scan-workflows/?per_page=1" | jq -r '.data[0].id')
api POST "/api/v1/scan-workflows/$SYSWF/clone" '{"name":"Subdomains of example.com (copy)"}' >/dev/null
MAP=$(api GET /api/v1/import-mappings/templates | jq -c '.items[0].mapping')
api POST /api/v1/import-mappings/ "{\"name\":\"web-scanner-csv\",\"description\":\"Weekly CSV export of the web scanner\",\"mapping\":$MAP,\"note\":\"first version\"}" >/dev/null
PROG='{"name":"Example Shop program","platform":"Example bounty platform","handle":"example-shop","program_url":"https://bugbounty.example.com/example-shop","scope_text":"In scope:\n*.shop.example.com\napi.example.com\n192.0.2.0/28\nOut of scope:\nblog.example.com","terms_text":"Test only the listed targets. No denial of service.","rules":{"rate_limit_rps":5,"user_agent":"bugbounty-researcher"}'
SHA=$(api POST /api/v1/programs/preview "$PROG}" | jq -r .terms_sha256)
api POST /api/v1/programs/ "$PROG,\"accept_terms_sha256\":\"$SHA\"}" >/dev/null

# Rows no API writes: an emerging-threat alert on two assets, a Jira site with
# a mapping draft (no credentials: nothing calls out), a pending confirmation.
MCPID=$(psql_ <<'SQL'
SELECT id AS tid FROM tenants WHERE slug = :'slug' \gset
SELECT id AS uid FROM users WHERE email = :'email' \gset
SELECT id AS web FROM assets WHERE tenant_id = :'tid' AND name = 'e2e-web.example.com' \gset
SELECT id AS app FROM assets WHERE tenant_id = :'tid' AND name = 'https://e2e-app.example.com' \gset

WITH a AS (
  INSERT INTO threat_alerts (tenant_id, vuln_id, title, severity, level, tier, ets, in_kev, epss,
                             confirmed_assets, possible_assets, internet_facing_assets, last_event_kind,
                             source_at, event_at)
  VALUES (:'tid', 'CVE-2099-0201', 'Remote code execution in the e2e request parser', 'critical', 'immediate',
          'confirmed', 87, true, 0.97, 1, 1, 1, 'kev_added', now() - interval '6 hours', now() - interval '5 hours')
  RETURNING id)
INSERT INTO threat_alert_assets (tenant_id, alert_id, asset_id, match_kind, confidence, internet_facing,
                                 criticality, product, version_seen, host_key)
SELECT :'tid', a.id, v.asset, v.kind, v.conf, v.inet, v.crit, v.product, v.version, v.host
FROM a, (VALUES (:'web'::uuid, 'confirmed', 95, true, 'high', 'e2e request parser', '2.4.1', 'e2e-web.example.com'),
                (:'app'::uuid, 'possible', 40, false, 'low', 'e2e request parser', '', 'e2e-app.example.com'))
        AS v(asset, kind, conf, inet, crit, product, version, host);

WITH i AS (
  INSERT INTO integrations (tenant_id, name, description, category, provider, status, auth_type, base_url,
                            last_sync_at, config, created_by)
  VALUES (:'tid', 'Jira (jira.example.com)', 'Security tickets', 'ticketing', 'jira', 'connected', 'basic',
          'https://jira.example.com', now() - interval '1 hour', '{}', :'uid')
  RETURNING id),
p AS (
  INSERT INTO ticket_mapping_profiles (tenant_id, integration_id, object_kind, project_id, project_key,
                                       issue_type_id, issue_type, name, draft_version, created_by)
  SELECT :'tid', i.id, 'finding', '10001', 'SEC', '10004', 'Bug', 'Security bugs to SEC', 1, :'uid' FROM i
  RETURNING id)
INSERT INTO ticket_mapping_versions (profile_id, tenant_id, version, state, spec, note, created_by)
SELECT p.id, :'tid', 1, 'draft', '{"minimization":"summary","comments_out":true,"comments_in":false,"status":{},"fields":[
  {"id":"summary","source":{"kind":"template","template":"[{{ finding.severity | upper }}] {{ finding.display_title | truncate:230 }}"},"target":{"field_id":"summary","name":"Summary","schema":{"type":"string","system":"summary"}},"direction":"out","sync":"always"},
  {"id":"priority","source":{"kind":"attr","attr":"finding.severity"},"target":{"field_id":"priority","name":"Priority","schema":{"type":"priority","system":"priority"}},"direction":"out","sync":"always","transform":{"kind":"value_map","map":{"critical":"Highest","high":"High","medium":"Medium","low":"Low","info":"Lowest"},"default":"Medium"}},
  {"id":"labels","source":{"kind":"attr","attr":"finding.cve_ids"},"target":{"field_id":"labels","name":"Labels","schema":{"type":"array","items":"string","system":"labels"}},"direction":"out","sync":"always","transform":{"kind":"list"}}]}'::jsonb,
  'created', :'uid' FROM p;

-- The legal pages (/privacy, /terms, /subprocessors, /dpa, /acceptable-use)
-- answer 404 until an administrator turns them on (Console > System > Legal).
INSERT INTO platform_settings (key, value, source)
VALUES ('legal', '{"pages_enabled":true,"organization_name":"Example Security Ltd","service_name":"OpenCTEM (example.com)",
  "contact_email":"legal@example.com","website_url":"https://www.example.com","address":"1 Example Street, Example City",
  "jurisdiction":"Example State","effective_date":"2099-01-01","security_contact":"security@example.com"}'::jsonb, 'console')
ON CONFLICT (key) DO UPDATE SET value = platform_settings.value || EXCLUDED.value,
  version = platform_settings.version + 1, updated_at = now();

WITH c AS (
  INSERT INTO mcp_oauth_clients (client_id, kind, tenant_id, name, redirect_uris)
  VALUES ('seed-ai-assistant-' || :'tid', 'organization', :'tid', 'Example AI assistant',
          '{https://ai-assistant.example.com/callback}')
  RETURNING id),
g AS (
  INSERT INTO mcp_oauth_grants (tenant_id, user_id, client_ref, resource, scopes, expires_at)
  SELECT :'tid', :'uid', c.id, 'https://openctem.example.com/mcp', '{findings:read,findings:write}',
         now() + interval '30 days' FROM c
  RETURNING id)
INSERT INTO mcp_action_confirmations (tenant_id, grant_id, user_id, tool, args_digest, summary, status, expires_at)
SELECT :'tid', g.id, :'uid', 'update_finding_status', encode(sha256('seed-confirm'::bytea), 'hex'),
       'Mark 3 findings on e2e-web.example.com as false positive (reason: detection error).', 'pending',
       now() + interval '7 days' FROM g
RETURNING id;
SQL
)
MCPID=$(grep -Eo '^[0-9a-f-]{36}$' <<<"$MCPID" | head -1)
[ -n "$MCPID" ] || { echo "seed-matrix: no confirmation id" >&2; exit 1; }
echo "E2E_MCP_CONFIRM_ID=$MCPID"
echo "seed-matrix: api keys, sla policies, channels, detail rows, legal pages added" >&2
