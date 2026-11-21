#!/usr/bin/env bash
# Seeds the e2e stack (web/e2e/ci/compose.yml) with what the Playwright specs
# need, then prints E2E_* variables (KEY=value lines) on stdout.
#
#   - an organization and its owner (bootstrap-admin), who signs in
#   - assets of two types, two sensors, a CTIS report with 15 findings
#     (enough for the findings picker to scroll; two name CVE-2099-0101) and 10 for the triage
#     spec, a scan with a run in progress, a remediation task
#   - an account that owns two organizations, A with 50 findings and B with 3
#     (the organization switch spec)
#
# Requires: docker (also runs psql from PSQL_IMAGE, default postgres:17-alpine), curl, jq. Env: API_IMAGE (runs /app/bootstrap-admin),
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
  # A distinct client address (the stack trusts its own networks as
  # proxies), so a step does not share the per-address limits of the others.
  [[ -n "${XFF:-}" ]] && args+=(-H "X-Forwarded-For: $XFF")
  [[ -n "$data" ]] && args+=(-d "$data")
  code=$(curl "${args[@]}")
  # Sign-in routes allow a few calls a minute per address: wait and retry.
  local tries=0
  while [[ "$code" == 429 && $tries -lt 8 ]]; do
    tries=$((tries + 1))
    sleep 10
    code=$(curl "${args[@]}")
  done
  BODY=$(cat "$WORK/body")
  if [[ ! "$code" =~ ^2 ]]; then
    log "$method $path -> $code: $(head -c 300 <<<"$BODY")"
    exit 1
  fi
}

log "organization and owner"
# Capture the output even when bootstrap-admin fails, so its error is printed.
# The output is captured, so -print-secrets; the URL goes in the environment.
setup=$(DATABASE_URL="$DATABASE_URL" docker run --rm --network "$NETWORK" -e DATABASE_URL \
  --entrypoint /app/bootstrap-admin "${API_IMAGE:?set API_IMAGE}" \
  -print-secrets \
  -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
  -org-name="E2E Org $RUN" -org-slug="$SLUG" -org-owner-email="$EMAIL" 2>&1) || {
  log "bootstrap-admin failed:"
  echo "$setup" >&2
  exit 1
}
# The link carries the token in the URL fragment (set-password#token=...), so it
# never reaches a server log or a Referer header.
TOKEN=$({ grep -o 'set-password#token=[^[:space:]]*' <<<"$setup" || true; } | head -1 | sed 's/.*token=//')
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

log "http services with service facts"
# 41-assets-service-facts: one service with more facts than a list cell holds
# (status, port, two addresses, a CNAME, an edge provider, TLS and four
# technologies), one with few. Technologies have no write endpoint (scanners
# report them), so the seed inserts them.
call POST /api/v1/assets '{"name":"https://e2e-edge.example.com","type":"http_service","criticality":"medium","properties":{"status_code":301,"port":443,"protocol":"https","scheme":"https","has_tls":true,"ip_addresses":["162.159.140.229","172.66.0.227"],"cname_target":"e2e-edge.example.com.cdn.cloudflare.net","cdn":"Cloudflare"}}'
EDGE_ID=$(jq -r .id <<<"$BODY")
call POST /api/v1/assets '{"name":"https://e2e-app.example.com","type":"http_service","criticality":"low","properties":{"status_code":200,"port":443,"protocol":"https","scheme":"https","has_tls":true}}'
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v asset="$EDGE_ID" >/dev/null <<'SQL'
INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, version, category, first_seen, last_seen)
SELECT a.tenant_id, a.id, t.k, t.n, t.v, t.c, now(), now()
  FROM assets a,
       (VALUES ('nginx', 'nginx', '1.25.3', 'web_server'), ('react', 'React', '18.3.1', 'js_library'),
               ('cloudflare', 'Cloudflare', '', 'cdn'), ('hsts', 'HSTS', '', 'security_header')) AS t(k, n, v, c)
 WHERE a.id = :'asset';
SQL

# 62-list-toolbar-stability (CVE catalog tab): the shared CVE catalog is filled
# by intelligence feeds, which a CI stack does not sync, so the seed inserts a
# few catalog entries (reserved 2099 block, none of the CVEs the findings above
# name). Global rows: no tenant.
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA >/dev/null <<'SQL'
INSERT INTO vulnerabilities (cve_id, external_id, namespace, origin, title, severity, cvss_score, epss_score,
                             exploit_available, exploit_maturity, cisa_kev_date_added, cisa_kev_due_date, published_at)
VALUES ('CVE-2099-0201', 'CVE-2099-0201', 'CVE', 'nvd', 'Remote code execution in the e2e request parser', 'critical', 9.8, 0.97, true, 'weaponized', '2099-01-02', '2099-01-23', '2099-01-01'),
       ('CVE-2099-0202', 'CVE-2099-0202', 'CVE', 'nvd', 'Path traversal in the e2e archive extractor', 'high', 8.1, 0.12, true, 'poc', NULL, NULL, '2099-01-05'),
       ('CVE-2099-0203', 'CVE-2099-0203', 'CVE', 'nvd', 'SQL injection in the e2e report filter', 'high', 7.5, 0.004, false, 'none', NULL, NULL, '2099-02-01'),
       ('CVE-2099-0204', 'CVE-2099-0204', 'CVE', 'nvd', 'Cross-site scripting in the e2e search page', 'medium', 6.1, 0.0004, false, 'none', NULL, NULL, '2099-02-10'),
       ('CVE-2099-0205', 'CVE-2099-0205', 'CVE', 'nvd', 'Information disclosure in the e2e status endpoint', 'low', 3.1, NULL, false, 'none', NULL, NULL, '2099-03-01')
ON CONFLICT DO NOTHING;
SQL

log "risk trend"
# Program health draws open findings over time from the daily risk snapshots
# (a controller writes them once a day): 90 days of them, the page's default
# window, so the trend chart and its screen-reader table render with a full
# series (31-page-rhythm, helpers/scroll-end.ts).
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v tid="$TENANT_ID" >/dev/null <<'SQL'
INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, risk_score_max, findings_open, p0_open, p1_open)
SELECT :'tid'::uuid, CURRENT_DATE - d, 40 + d % 7, 80, 120 - d, d % 3, 2 + d % 4
  FROM generate_series(1, 90) AS d;
SQL

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
# promotes the sensor and allows push ingest, as an administrator would, and
# raises its tier ceiling so workflow scans of active steps can be saved
# (19-scan-lifecycle).
call GET "/api/v1/sensors/$SENSOR_ID/grant"
GRANT=$(jq -c '.trust_level = "trusted" | .allow_push_ingest = true | .tier_ceiling = 2
  | del(.sensor_id, .legacy_broad, .updated_at, .effective, .profile)' <<<"$BODY")
call PUT "/api/v1/sensors/$SENSOR_ID/grant" "$GRANT"
call POST /api/v1/sensors '{"name":"e2e-sensor-b","type":"worker","execution_mode":"daemon","tools":["nuclei"],"capabilities":["vulnerability"]}'

# A heartbeat brings e2e-sensor online and reports nuclei as installed. Ingest
# accepts a report only from a tool the sensor has reported (sensors.tools was
# dropped, #1254), and dispatch counts only reported tools too (#824). Nothing
# claims the scan's job below, so its run stays in progress for
# 10-scan-detail-runs. It reports a release and an SDK pseudo-version (a
# build of an unreleased commit, 40 characters): the drawer specs check that
# a value that long stays inside its column (30-drawer-text-layout).
#
# Its local policy is reported in two steps. A sensor that requires a local
# policy and has none refuses every job with a target (it fails closed), so
# the scan below could not be triggered while it is reported that way. The
# first heartbeat reports no policy at all (the platform's scope decides);
# the second, after the trigger, reports the policy absent while required, so
# the sensor's drawer offers the suggested policy (41-sensor-policy-suggestion).
heartbeat() {
  local policy=$1 code
  code=$(curl -sS -o "$WORK/body" -w '%{http_code}' -X POST "$API/api/v2/sensor/heartbeat" \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d '{"status":"online","version":"v0.25.0","scanners":["nuclei"],"tools":[{"name":"nuclei","kind":"scanner","installed":true}],"sdk":{"name":"openctem-sdk-go","version":"v0.37.1-0.20261025003926-6373f2417870"},"sensor":{"name":"openctem-sensor","version":"v0.25.0"}'"$policy"'}')
  [[ "$code" =~ ^2 ]] || { log "heartbeat -> $code: $(head -c 300 "$WORK/body")"; exit 1; }
}
heartbeat ''

findings=$({
  for i in $(seq 1 15); do
    # The first two (one per asset) name one CVE: the vulnerability page spec
    # (40) opens it. Two findings of one CVE on one asset would be merged.
    cve=''
    [[ $i -le 2 ]] && cve=',"vulnerability":{"ids":[{"type":"cve","id":"CVE-2099-0101"}]}'
    printf '{"type":"vulnerability","title":"E2E finding %02d","severity":"%s","rule_id":"e2e-%02d","asset_ref":"a%d","description":"e2e"%s}\n' \
      "$i" "$([[ $((i % 3)) == 0 ]] && echo critical || echo medium)" "$i" "$((i % 2 + 1))" "$cve"
  done
  # Ten more for the triage mode spec (36-findings-triage-mode), which decides
  # them: no other spec reads them.
  for i in $(seq 1 10); do
    printf '{"type":"vulnerability","title":"E2E triage %02d","severity":"high","rule_id":"e2e-tri-%02d","asset_ref":"a1","description":"e2e triage"}\n' \
      "$i" "$i"
  done
  # One web finding with the proof nuclei sends (an HTTP exchange, then its
  # curl item) for the drawer evidence spec (31-finding-drawer-evidence). The
  # Authorization value must arrive masked; no other spec reads it.
  jq -nc '{
    type: "vulnerability", title: "E2E evidence 01", severity: "low",
    rule_id: "e2e-evidence-01", asset_ref: "a1", description: "e2e evidence",
    evidence_items: [
      { kind: "http_exchange",
        http: {
          request: { method: "GET", url: "https://e2e-web.example.com/wp-admin/js/theme.js",
            http_version: "HTTP/1.1",
            headers: [ { name: "Host", value: "e2e-web.example.com" },
                       { name: "Authorization", value: "Bearer e2e-not-a-real-token-0001" } ] },
          response: { status: 200, reason: "OK", http_version: "HTTP/1.1",
            headers: [ { name: "Content-Type", value: "text/html" },
                       { name: "Server", value: "e2e" } ],
            body: "<html><script>window.__pwned=1</script> e2e theme preview wp-version 7.1.0</html>" } },
        match: [ { location: "response", part: "body", start: 69, end: 74, matcher: "version" } ],
        extracted: [ "{\"link\":\"https:\\/\\/e2e-web.example.com\\/wp-json\\/tribe\\/events\\/v1\\/organizers\\/?id=24148&status=publish\",\"global_id_lineage\":[\"e2e-web.example.com?id=24148\"]}" ] },
      { kind: "curl",
        text: "curl -X GET -H \"Authorization: Bearer e2e-not-a-real-token-0001\" https://e2e-web.example.com/wp-admin/js/theme.js" }
    ]
  }'
} | jq -s .)
# The report goes to the v2 results resource (one PUT is a whole report).
# CTIS 2.0: metadata.id is the producer's UUIDv7 (here the same value as the
# report id of the URL, which binds the delivery).
ms=$(printf '%012x' "$(date +%s%3N)"); rnd=$(openssl rand -hex 10)
REPORT_ID="${ms:0:8}-${ms:8:4}-7${rnd:0:3}-$(printf '%x' $(( (0x${rnd:3:1} & 3) | 8 )))${rnd:4:3}-${rnd:8:12}"
jq -n --arg id "$REPORT_ID" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson findings "$findings" '{
  version: "2.0",
  metadata: { id: $id, generated_at: $ts, channel: "scanner" },
  tool: { name: "nuclei", version: "3.3.0" },
  assets: [
    { id: "a1", type: "domain_name", value: "e2e-web.example.com" },
    { id: "a2", type: "domain_name", value: "e2e-api.example.com" }
  ],
  findings: $findings
}' >"$WORK/report.json"
DIGEST=$(openssl dgst -sha256 -binary "$WORK/report.json" | base64)
code=$(curl -sS -o "$WORK/body" -w '%{http_code}' -X PUT "$API/api/v2/sensor/results/$REPORT_ID" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/vnd.ctis+json; version=2.0' \
  -H "Content-Digest: sha-256=:$DIGEST:" --data-binary @"$WORK/report.json")
[[ "$code" =~ ^2 ]] || { log "ingest -> $code: $(head -c 300 "$WORK/body")"; exit 1; }

log "credential leaks"
# /credentials (specs 36 and 62): a list with rows, so its toolbar, chips and
# grouping are drawn. Every severity, four sources, one long identifier, one
# leak dated today ("Recent"), one without a breach date. No secret values.
TODAY=$(date -u +%F)
call POST /api/v1/credentials/import "{\"credentials\":[
  {\"identifier\":\"e2e-alice@example.com\",\"credential_type\":\"password\",\"severity\":\"critical\",\"source\":{\"type\":\"data_breach\",\"name\":\"e2e breach\"},\"dedup_key\":{\"breach_name\":\"e2e breach\",\"breach_date\":\"$TODAY\"},\"context\":{\"email\":\"e2e-alice@example.com\",\"username\":\"alice\"}},
  {\"identifier\":\"e2e-alice@example.com\",\"credential_type\":\"access_token\",\"severity\":\"high\",\"source\":{\"type\":\"dark_web\"},\"dedup_key\":{\"breach_name\":\"e2e market\",\"breach_date\":\"2024-03-01\"},\"context\":{\"email\":\"e2e-alice@example.com\"}},
  {\"identifier\":\"e2e-ci-deploy-key\",\"credential_type\":\"api_key\",\"severity\":\"medium\",\"source\":{\"type\":\"code_repository\"},\"dedup_key\":{\"repository\":\"example.com/e2e/app\",\"file_path\":\"deploy/ci.env\"}},
  {\"identifier\":\"e2e-a-very-long-service-account-name-for-the-reporting-pipeline@example.com\",\"credential_type\":\"refresh_token\",\"severity\":\"low\",\"source\":{\"type\":\"paste_site\"},\"dedup_key\":{\"paste_id\":\"e2e-paste-1\"}},
  {\"identifier\":\"e2e-bob\",\"credential_type\":\"password\",\"severity\":\"info\",\"source\":{\"type\":\"data_breach\",\"name\":\"e2e old breach\"},\"dedup_key\":{\"breach_name\":\"e2e old breach\",\"breach_date\":\"2019-07-15\"},\"context\":{\"username\":\"e2e-bob\"}}
]}"

log "a scan with a run in progress"
call POST /api/v1/scans/ '{"name":"E2E scan","scan_type":"single","scanner_name":"nuclei","targets":["e2e-web.example.com"],"schedule_type":"manual"}'
call POST "/api/v1/scans/$(jq -r .id <<<"$BODY")/trigger" '{}'
heartbeat ',"local_policy":{"state":"absent","required":true}'

log "remediation campaign"
call POST /api/v1/remediation/campaigns '{"name":"E2E remediation campaign","description":"e2e","priority":"high"}'

# Ingest is asynchronous: wait until the findings are listed.
for _ in $(seq 1 30); do
  call GET "/api/v1/findings?per_page=50"
  n=$(jq -r '[.data[]? | select(.title|startswith("E2E finding"))] | length' <<<"$BODY")
  nt=$(jq -r '[.data[]? | select(.title|startswith("E2E triage"))] | length' <<<"$BODY")
  [[ "$n" -ge 15 && "$nt" -ge 10 ]] && break
  sleep 1
done
[[ "$n" -ge 15 && "$nt" -ge 10 ]] || { log "only $n of 15 findings and $nt of 10 triage findings visible"; exit 1; }

log "remediation tasks (the tasks and campaigns lists)"
# Two tasks of the seed findings, one in the campaign with a due date, so the
# lists show progress, owners, deadlines and a campaign with tasks.
FIDS=$(jq -c '[.data[]? | select(.title|startswith("E2E finding")) | .id]' <<<"$BODY")
call GET "/api/v1/remediation/campaigns?per_page=5"
CAMPAIGN_ID=$(jq -r '[.data[]? | select(.name=="E2E remediation campaign")][0].id // empty' <<<"$BODY")
DUE=$(date -u -d '+5 days' +%Y-%m-%dT00:00:00Z 2>/dev/null || date -u -v+5d +%Y-%m-%dT00:00:00Z)
call POST /api/v1/remediation/tasks "{\"title\":\"E2E upgrade OpenSSH on the edge hosts\",\"finding_ids\":$(jq -c '.[0:3]' <<<"$FIDS"),\"deadline\":\"$DUE\"${CAMPAIGN_ID:+,\"campaign_id\":\"$CAMPAIGN_ID\"}}"
call POST /api/v1/remediation/tasks "{\"title\":\"E2E renew the certificate on shop.example.com\",\"finding_ids\":$(jq -c '.[3:4]' <<<"$FIDS")}"

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
# Registering with the invitation token is the way in when public sign-up is
# off (SIGNUP_MODE=disabled, the default); it also proves the address.
call POST /api/v1/auth/register "{\"email\":\"$MEMBER_EMAIL\",\"password\":\"$MEMBER_PASSWORD\",\"name\":\"E2E Member\",\"invitation_token\":\"$INVITE_TOKEN\"}"
call POST /api/v1/auth/login "{\"email\":\"$MEMBER_EMAIL\",\"password\":\"$MEMBER_PASSWORD\"}"
call POST /api/v1/invitations/accept-with-refresh "{\"token\":\"$INVITE_TOKEN\",\"refresh_token\":\"$(jq -r '.refresh_token // empty' <<<"$BODY")\"}"
call POST /api/v1/auth/logout '{}'

log "an account in two organizations (E2E_SWITCH_*)"
# 56-organization-switch signs in as an account that belongs to two
# organizations of its own and switches between them. The main owner keeps
# one organization (with two, every spec's sign-in would stop at the
# organization picker). Organization A gets enough findings for a fifth page
# of ten, B a few: the spec tells them apart by id.
SWITCH_EMAIL="e2e-switch-$RUN@openctem-test.local"
SWITCH_PASSWORD="$(openssl rand -hex 10)S$(openssl rand -hex 3)"
SWITCH_TOKEN=
for which in A B; do
  slug="$SLUG-switch-$(tr 'AB' 'ab' <<<"$which")"
  # The same administrator as above (left unchanged); the second run names
  # the account the first one created, which then owns both.
  out=$(DATABASE_URL="$DATABASE_URL" docker run --rm --network "$NETWORK" -e DATABASE_URL \
    --entrypoint /app/bootstrap-admin "${API_IMAGE:?set API_IMAGE}" \
    -print-secrets \
    -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
    -org-name="E2E Switch $which $RUN" -org-slug="$slug" -org-owner-email="$SWITCH_EMAIL" 2>&1) || {
    log "bootstrap-admin (switch $which) failed:"
    echo "$out" >&2
    exit 1
  }
  if [[ "$which" == A ]]; then
    SWITCH_TOKEN=$({ grep -o 'set-password#token=[^[:space:]]*' <<<"$out" || true; } | head -1 | sed 's/.*token=//')
    [[ -n "$SWITCH_TOKEN" ]] || { log "no set-password link for $SWITCH_EMAIL:"; echo "$out" >&2; exit 1; }
  fi
done
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v a="$SLUG-switch-a" -v b="$SLUG-switch-b" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb)
 WHERE slug IN (:'a', :'b');
SQL
ACCESS_TOKEN=
JAR="$WORK/switch-cookies"
call POST /api/v1/auth/reset-password "{\"token\":\"$SWITCH_TOKEN\",\"new_password\":\"$SWITCH_PASSWORD\"}"
call POST /api/v1/auth/login "{\"email\":\"$SWITCH_EMAIL\",\"password\":\"$SWITCH_PASSWORD\"}"
LOGIN_BODY="$BODY"
for which in A B; do
  slug="$SLUG-switch-$(tr 'AB' 'ab' <<<"$which")"
  tid=$(jq -r --arg s "$slug" '(.tenants // [])[] | select(.slug==$s) | .id' <<<"$LOGIN_BODY")
  [[ -n "$tid" ]] || { log "login of $SWITCH_EMAIL lists no $slug"; exit 1; }
  ACCESS_TOKEN=
  call POST /api/v1/auth/token "{\"tenant_id\":\"$tid\"}"
  ACCESS_TOKEN=$(jq -r .access_token <<<"$BODY")
  call POST /api/v1/assets "{\"name\":\"switch-$(tr 'AB' 'ab' <<<"$which").example.com\",\"type\":\"domain\",\"criticality\":\"medium\"}"
  asset=$(jq -r '.id // .data.id' <<<"$BODY")
  count=$([[ "$which" == A ]] && echo 50 || echo 3)
  for i in $(seq 1 "$count"); do
    call POST /api/v1/findings "$(printf '{"asset_id":"%s","source":"manual","tool_name":"e2e","rule_id":"switch-%s-%02d","message":"Switch %s finding %02d","severity":"high"}' \
      "$asset" "$which" "$i" "$which" "$i")"
  done
done

# 57-invitation-accept: two pending invitations into organization B, one for
# an account with an organization of its own (E2E_INVITEE_*), one for an
# account with none yet (E2E_INVITEE_NEW_*). Not into the main organization:
# its members page would then read the roles of pending invitations, past
# that page's request budget (16-request-budget).
call GET /api/v1/roles
INVITE_ROLE_ID=$(jq -r '[(.roles // .data // .)[] | select((.slug // .name | ascii_downcase) == "member")][0].id' <<<"$BODY")
[[ -n "$INVITE_ROLE_ID" && "$INVITE_ROLE_ID" != null ]] || { log "no member role in $SLUG-switch-b"; exit 1; }
INVITEE_EMAIL="e2e-invitee-$RUN@openctem-test.local"
INVITEE_PASSWORD="$(openssl rand -hex 10)I$(openssl rand -hex 3)"
call POST "/api/v1/tenants/$SLUG-switch-b/invitations" "{\"email\":\"$INVITEE_EMAIL\",\"role_ids\":[\"$INVITE_ROLE_ID\"]}"
INVITEE_TOKEN=$(jq -r .token <<<"$BODY")
INVITEE_NEW_EMAIL="e2e-invitee-new-$RUN@openctem-test.local"
INVITEE_NEW_PASSWORD="$(openssl rand -hex 10)N$(openssl rand -hex 3)"
call POST "/api/v1/tenants/$SLUG-switch-b/invitations" "{\"email\":\"$INVITEE_NEW_EMAIL\",\"role_ids\":[\"$INVITE_ROLE_ID\"]}"
INVITEE_NEW_TOKEN=$(jq -r .token <<<"$BODY")
if [[ -n "${E2E_FAKE_GOOGLE:-}" ]]; then
  # 66-first-sign-in: a pending invitation into organization B for an address
  # that signs in with Google for the first time (closed sign-up admits it).
  SOCIAL_INVITED_EMAIL="e2e-social-invited-$RUN@openctem-test.local"
  call POST "/api/v1/tenants/$SLUG-switch-b/invitations" "{\"email\":\"$SOCIAL_INVITED_EMAIL\",\"role_ids\":[\"$INVITE_ROLE_ID\"]}"
fi
call POST /api/v1/auth/logout '{}'

log "invitees (E2E_INVITEE_*)"
# The first invitee owns an organization of its own (its home); the second
# registers with its invitation token and has no organization. Neither
# accepts here: 57-invitation-accept does, in the browser.
out=$(DATABASE_URL="$DATABASE_URL" docker run --rm --network "$NETWORK" -e DATABASE_URL \
  --entrypoint /app/bootstrap-admin "${API_IMAGE:?set API_IMAGE}" \
  -print-secrets \
  -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
  -org-name="E2E Invitee Home $RUN" -org-slug="$SLUG-invitee-home" -org-owner-email="$INVITEE_EMAIL" 2>&1) || {
  log "bootstrap-admin (invitee) failed:"
  echo "$out" >&2
  exit 1
}
INVITEE_SET_TOKEN=$({ grep -o 'set-password#token=[^[:space:]]*' <<<"$out" || true; } | head -1 | sed 's/.*token=//')
[[ -n "$INVITEE_SET_TOKEN" ]] || { log "no set-password link for $INVITEE_EMAIL:"; echo "$out" >&2; exit 1; }
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG-invitee-home" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb)
 WHERE slug = :'slug';
SQL
ACCESS_TOKEN=
JAR="$WORK/invitee-cookies"
call POST /api/v1/auth/reset-password "{\"token\":\"$INVITEE_SET_TOKEN\",\"new_password\":\"$INVITEE_PASSWORD\"}"
JAR="$WORK/invitee-new-cookies"
call POST /api/v1/auth/register "{\"email\":\"$INVITEE_NEW_EMAIL\",\"password\":\"$INVITEE_NEW_PASSWORD\",\"name\":\"E2E Invitee\",\"invitation_token\":\"$INVITEE_NEW_TOKEN\"}"

if [[ -n "${E2E_FAKE_GOOGLE:-}" ]]; then
  log "an organization that requires two-factor authentication (E2E_MFA_ORG*)"
  # 66-first-sign-in: invitations into it for a first Google sign-in and for a
  # new password account; the requirement is turned on after the owner has
  # sent them (an owner without 2FA could not open it afterwards).
  MFA_OWNER_EMAIL="e2e-2fa-owner-$RUN@openctem-test.local"
  MFA_OWNER_PASSWORD="$(openssl rand -hex 10)M$(openssl rand -hex 3)"
  out=$(DATABASE_URL="$DATABASE_URL" docker run --rm --network "$NETWORK" -e DATABASE_URL \
    --entrypoint /app/bootstrap-admin "${API_IMAGE:?set API_IMAGE}" \
    -print-secrets \
    -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
    -org-name="E2E 2FA $RUN" -org-slug="$SLUG-2fa" -org-owner-email="$MFA_OWNER_EMAIL" 2>&1) || {
    log "bootstrap-admin (2fa) failed:"
    echo "$out" >&2
    exit 1
  }
  MFA_SET_TOKEN=$({ grep -o 'set-password#token=[^[:space:]]*' <<<"$out" || true; } | head -1 | sed 's/.*token=//')
  [[ -n "$MFA_SET_TOKEN" ]] || { log "no set-password link for $MFA_OWNER_EMAIL"; exit 1; }
  docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG-2fa" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb)
 WHERE slug = :'slug';
SQL
  ACCESS_TOKEN=
  JAR="$WORK/mfa-owner-cookies"
  call POST /api/v1/auth/reset-password "{\"token\":\"$MFA_SET_TOKEN\",\"new_password\":\"$MFA_OWNER_PASSWORD\"}"
  call POST /api/v1/auth/login "{\"email\":\"$MFA_OWNER_EMAIL\",\"password\":\"$MFA_OWNER_PASSWORD\"}"
  MFA_TENANT_ID=$(jq -r --arg s "$SLUG-2fa" '(.tenants // [])[] | select(.slug==$s) | .id' <<<"$BODY")
  call POST /api/v1/auth/token "{\"tenant_id\":\"$MFA_TENANT_ID\"}"
  ACCESS_TOKEN=$(jq -r .access_token <<<"$BODY")
  call GET /api/v1/roles
  MFA_ROLE_ID=$(jq -r '[(.roles // .data // .)[] | select((.slug // .name | ascii_downcase) == "member")][0].id' <<<"$BODY")
  SOCIAL_MFA_EMAIL="e2e-social-2fa-$RUN@openctem-test.local"
  call POST "/api/v1/tenants/$SLUG-2fa/invitations" "{\"email\":\"$SOCIAL_MFA_EMAIL\",\"role_ids\":[\"$MFA_ROLE_ID\"]}"
  PASSWORD_MFA_EMAIL="e2e-password-2fa-$RUN@openctem-test.local"
  PASSWORD_MFA_PASSWORD="$(openssl rand -hex 10)P$(openssl rand -hex 3)"
  call POST "/api/v1/tenants/$SLUG-2fa/invitations" "{\"email\":\"$PASSWORD_MFA_EMAIL\",\"role_ids\":[\"$MFA_ROLE_ID\"]}"
  PASSWORD_MFA_TOKEN=$(jq -r .token <<<"$BODY")
  call POST /api/v1/auth/logout '{}'
  ACCESS_TOKEN=
  JAR="$WORK/password-2fa-cookies"
  call POST /api/v1/auth/register "{\"email\":\"$PASSWORD_MFA_EMAIL\",\"password\":\"$PASSWORD_MFA_PASSWORD\",\"name\":\"E2E Password 2FA\",\"invitation_token\":\"$PASSWORD_MFA_TOKEN\"}"
  docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$SLUG-2fa" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required": true}'::jsonb)
 WHERE slug = :'slug';
SQL
fi
log "sign-in journeys organization (E2E_JOURNEY_*)"
# 58-sign-in-journeys: one organization whose rules the spec switches per
# journey (open, two-factor required, identity provider required). Its owner
# signs in with a password; the spec seeds people and their sessions itself.
JOURNEY_SLUG="$SLUG-journeys"
JOURNEY_OWNER_EMAIL="e2e-journeys-owner-$RUN@openctem-test.local"
out=$(DATABASE_URL="$DATABASE_URL" docker run --rm --network "$NETWORK" -e DATABASE_URL \
  --entrypoint /app/bootstrap-admin "${API_IMAGE:?set API_IMAGE}" \
  -print-secrets \
  -email="e2e-admin-$RUN@openctem-test.local" -no-backup \
  -org-name="E2E Journeys $RUN" -org-slug="$JOURNEY_SLUG" -org-owner-email="$JOURNEY_OWNER_EMAIL" 2>&1) || {
  log "bootstrap-admin (journeys) failed:"
  echo "$out" >&2
  exit 1
}
JOURNEY_SET_TOKEN=$({ grep -o 'set-password#token=[^[:space:]]*' <<<"$out" || true; } | head -1 | sed 's/.*token=//')
[[ -n "$JOURNEY_SET_TOKEN" ]] || { log "no set-password link for $JOURNEY_OWNER_EMAIL:"; echo "$out" >&2; exit 1; }
docker run --rm -i --network "$NETWORK" -e PGCONNECT_TIMEOUT=10 "${PSQL_IMAGE:-postgres:17-alpine}" \
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtA -v slug="$JOURNEY_SLUG" >/dev/null <<'SQL'
UPDATE tenants
   SET settings = settings || jsonb_build_object('security',
         COALESCE(settings->'security', '{}'::jsonb) || '{"mfa_required_for_admins": false}'::jsonb)
 WHERE slug = :'slug';
SQL
ACCESS_TOKEN=
JAR="$WORK/journeys-cookies"
XFF=198.18.250.1
call POST /api/v1/auth/reset-password "{\"token\":\"$JOURNEY_SET_TOKEN\",\"new_password\":\"$OWNER_PASSWORD\"}"
XFF=

log "done"
echo "E2E_USER_EMAIL=$EMAIL"
echo "E2E_USER_PASSWORD=$OWNER_PASSWORD"
echo "E2E_TENANT_SLUG=$SLUG"
echo "E2E_LIMITED_EMAIL=$MEMBER_EMAIL"
echo "E2E_LIMITED_PASSWORD=$MEMBER_PASSWORD"
echo "E2E_SWITCH_EMAIL=$SWITCH_EMAIL"
echo "E2E_SWITCH_PASSWORD=$SWITCH_PASSWORD"
echo "E2E_SWITCH_ORG_A=E2E Switch A $RUN"
echo "E2E_SWITCH_ORG_B=E2E Switch B $RUN"
echo "E2E_INVITE_ORG=E2E Switch B $RUN"
echo "E2E_INVITE_ORG_SLUG=$SLUG-switch-b"
echo "E2E_INVITEE_EMAIL=$INVITEE_EMAIL"
echo "E2E_INVITEE_PASSWORD=$INVITEE_PASSWORD"
echo "E2E_INVITEE_TOKEN=$INVITEE_TOKEN"
echo "E2E_INVITEE_HOME_ORG=E2E Invitee Home $RUN"
echo "E2E_INVITEE_NEW_EMAIL=$INVITEE_NEW_EMAIL"
echo "E2E_INVITEE_NEW_PASSWORD=$INVITEE_NEW_PASSWORD"
echo "E2E_INVITEE_NEW_TOKEN=$INVITEE_NEW_TOKEN"
if [[ -n "${E2E_FAKE_GOOGLE:-}" ]]; then
  echo "E2E_FAKE_GOOGLE=1"
  echo "E2E_SOCIAL_NEW_EMAIL=e2e-social-new-$RUN@openctem-test.local"
  echo "E2E_SOCIAL_INVITED_EMAIL=$SOCIAL_INVITED_EMAIL"
  echo "E2E_SOCIAL_MFA_EMAIL=$SOCIAL_MFA_EMAIL"
  echo "E2E_PASSWORD_MFA_EMAIL=$PASSWORD_MFA_EMAIL"
  echo "E2E_PASSWORD_MFA_PASSWORD=$PASSWORD_MFA_PASSWORD"
  echo "E2E_MFA_ORG=E2E 2FA $RUN"
  echo "E2E_MFA_ORG_SLUG=$SLUG-2fa"
fi
echo "E2E_JOURNEY_SLUG=$JOURNEY_SLUG"
echo "E2E_JOURNEY_OWNER_EMAIL=$JOURNEY_OWNER_EMAIL"
echo "E2E_JOURNEY_OWNER_PASSWORD=$OWNER_PASSWORD"
echo "E2E_JOURNEY_NETWORK=$NETWORK"
