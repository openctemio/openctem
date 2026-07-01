#!/bin/bash
# =============================================================================
# E2E cross-component flow — Agent → API ingest
# =============================================================================
# Validates the agent↔API boundary: create an agent, get its API key, POST a
# CTIS report to the agent ingest endpoint (X-API-Key auth), and verify the
# assets/findings land + are queryable via the user API. Also checks the auth
# boundary (bad key → 401).
#
#   ./test_e2e_agent_ingest.sh [API_URL]
# =============================================================================
source "$(cd "$(dirname "$0")" && pwd)/_e2e_common.sh"
e2e_init "agent-ingest"
e2e_bootstrap_auth
A="$(auth_hdr)"

print_test "create agent"
do_request POST /api/v1/agents "{
    \"name\":\"e2e-agent-${TIMESTAMP}\",\"type\":\"runner\",
    \"description\":\"e2e ingest agent\",\"capabilities\":[\"sast\",\"sca\"],
    \"execution_mode\":\"standalone\",\"max_concurrent_jobs\":5}" "$A"
assert_status "200|201" "create agent"
API_KEY=$(extract_json "$BODY" '.api_key')
assert_json '.api_key != null and (.api_key|length) > 10' "agent returned an api_key"

CTIS=$(cat <<EOF
{
  "version":"1.0",
  "metadata":{"id":"e2e-ctis-${TIMESTAMP}","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","source_type":"scanner"},
  "tool":{"name":"e2e-scanner","version":"1.0.0"},
  "assets":[{"id":"a1","type":"repository","value":"github.com/test/e2e-${TIMESTAMP}","name":"E2E Repo","criticality":"high"}],
  "findings":[
    {"id":"f-sqli","type":"vulnerability","title":"SQL Injection","description":"unparameterized query","severity":"critical","confidence":90,"rule_id":"e2e.sqli","asset_ref":"a1","location":{"path":"src/login.go","start_line":42,"end_line":42},"vulnerability":{"cwe_ids":["CWE-89"],"cvss_score":9.8}},
    {"id":"f-secret","type":"secret","title":"AWS key exposed","description":"hardcoded key","severity":"high","confidence":90,"rule_id":"e2e.aws","asset_ref":"a1","location":{"path":"config.yaml","start_line":5,"end_line":5}}
  ]
}
EOF
)

# --- auth boundary: ingest with a bad key must be rejected ------------------
print_test "ingest with INVALID api key -> 401"
do_request POST /api/v1/agent/ingest/ctis "$CTIS" "X-API-Key: oct_invalid_key_000000000000000000000000"
assert_status "401" "bad api key rejected"

# --- happy path: ingest with the real key ----------------------------------
print_test "ingest CTIS report (X-API-Key)"
do_request POST /api/v1/agent/ingest/ctis "$CTIS" "X-API-Key: $API_KEY"
if echo "$HTTP_CODE" | grep -qE '^(200|201|202)$'; then
    print_success "ingest accepted (HTTP $HTTP_CODE)"
    print_info "assets_created=$(extract_json "$BODY" '.assets_created // .assets // "?"') findings_created=$(extract_json "$BODY" '.findings_created // .findings // "?"')"
else
    print_failure "ingest" "HTTP $HTTP_CODE — $(echo "$BODY" | head -c 300)"
fi

# --- verify the ingested data is queryable via the user API ----------------
# async ingest (RFC-005) may enqueue; poll findings a few times.
print_test "ingested finding is queryable via /findings"
found=0
for i in 1 2 3 4 5; do
    do_request GET "/api/v1/findings?search=SQL%20Injection&per_page=50" "" "$A"
    if echo "$BODY" | jq -e '((.data // .items // []) | length) >= 1' >/dev/null 2>&1; then found=1; break; fi
    do_request GET "/api/v1/findings?per_page=100" "" "$A"
    if echo "$BODY" | jq -e '((.data // .items // []) | map(select(.title|test("SQL Injection"))) | length) >= 1' >/dev/null 2>&1; then found=1; break; fi
    sleep 2
done
[ "$found" = "1" ] && print_success "ingested finding surfaced in /findings" \
    || print_failure "ingested finding not found" "(async ingest may still be draining)"

# --- ingested asset is queryable -------------------------------------------
print_test "ingested asset is queryable via /assets"
do_request GET "/api/v1/assets?per_page=100" "" "$A"
assert_json '((.data // .items // []) | length) >= 1' "assets present after ingest"

e2e_finish
