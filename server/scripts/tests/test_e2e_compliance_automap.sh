#!/usr/bin/env bash
# E2E: deterministic compliance auto-mapping (findings -> OWASP Top 10 controls).
# Create a finding, classify it with a CWE (SQLi → A03) + an OWASP id, then
# auto-map and assert an OWASP control mapping was created.
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_e2e_common.sh
. ./_e2e_common.sh

e2e_init "compliance auto-map (OWASP)"
e2e_bootstrap_auth

TS="$(date +%s)"

do_request POST /api/v1/assets \
  "{\"name\":\"automap-${TS}.example.com\",\"type\":\"domain\",\"criticality\":\"high\"}" "$(auth_hdr)"
assert_status "200|201" "create asset"
ASSET_ID="$(extract_json "$BODY" '.id')"

do_request POST /api/v1/findings \
  "{\"asset_id\":\"$ASSET_ID\",\"source\":\"sast\",\"tool_name\":\"e2e\",\"rule_id\":\"sqli-${TS}\",\"message\":\"SQL injection\",\"severity\":\"high\"}" "$(auth_hdr)"
assert_status "200|201" "create finding"
FINDING_ID="$(extract_json "$BODY" '.id')"

# Confirm (so the finding is not draft/in_review) then classify with a CWE + OWASP id.
do_request POST /api/v1/findings/bulk/status \
  "{\"finding_ids\":[\"$FINDING_ID\"],\"status\":\"confirmed\"}" "$(auth_hdr)"
assert_status "200|201" "confirm finding"

do_request PATCH "/api/v1/findings/$FINDING_ID/classify" \
  "{\"cwe_ids\":[\"CWE-89\"],\"owasp_ids\":[\"A03:2021\"]}" "$(auth_hdr)"
assert_status "200|201" "classify finding with CWE-89 + A03"

# Auto-map → expect at least one OWASP control mapping created.
do_request POST "/api/v1/compliance/findings/$FINDING_ID/controls/auto-map" "" "$(auth_hdr)"
assert_status "200" "auto-map finding to OWASP controls"
assert_json '.count >= 1' "auto-map created at least one mapping"

# Idempotency: a second auto-map creates nothing new.
do_request POST "/api/v1/compliance/findings/$FINDING_ID/controls/auto-map" "" "$(auth_hdr)"
assert_status "200" "auto-map again (idempotent)"
assert_json '.count == 0' "second auto-map is a no-op"

# The mapping is visible on the finding's controls list.
do_request GET "/api/v1/compliance/findings/$FINDING_ID/controls" "" "$(auth_hdr)"
assert_status "200" "list finding controls"
assert_json '(.data // . ) | length >= 1' "finding now has at least one control mapping"

e2e_finish
