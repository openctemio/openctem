#!/usr/bin/env bash
# E2E: CTEM Stage-4 Validation Engine (RFC-010).
# Proves the full loop on WIRED transport:
#   POST /findings/{id}/validate  -> enqueues a `validate` tenant command (202)
#   agent polls/ack/start/complete the command with an outcome
#   command-completion hook maps the result -> validation evidence
#   GET /findings/{id}/evidence   -> shows the recorded evidence
#   finding status reconciled from the outcome (fix_applied -> resolved)
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_e2e_common.sh
. ./_e2e_common.sh

e2e_init "validation engine (RFC-010)"
e2e_bootstrap_auth

TS="$(date +%s)"

# --- Asset + finding under test --------------------------------------------
do_request POST /api/v1/assets \
  "{\"name\":\"validate-${TS}.example.com\",\"type\":\"domain\",\"criticality\":\"high\"}" \
  "$(auth_hdr)"
assert_status "200|201" "create asset"
ASSET_ID="$(extract_json "$BODY" '.id')"

do_request POST /api/v1/findings \
  "{\"asset_id\":\"$ASSET_ID\",\"source\":\"sast\",\"tool_name\":\"e2e\",\"rule_id\":\"val-${TS}\",\"message\":\"validation engine e2e\",\"severity\":\"high\"}" \
  "$(auth_hdr)"
assert_status "200|201" "create finding"
FINDING_ID="$(extract_json "$BODY" '.id')"

# Walk new -> confirmed -> in_progress -> fix_applied. Validation only auto-
# resolves a finding that is in `fix_applied` (the proof-of-fix state): a
# reachability probe returning not_detected on a merely-`confirmed` finding is
# NOT proof the vuln is fixed, so the engine leaves confirmed findings untouched.
do_request POST /api/v1/findings/bulk/status \
  "{\"finding_ids\":[\"$FINDING_ID\"],\"status\":\"confirmed\"}" \
  "$(auth_hdr)"
assert_status "200|201" "confirm finding"

do_request POST /api/v1/findings/bulk/status \
  "{\"finding_ids\":[\"$FINDING_ID\"],\"status\":\"in_progress\"}" \
  "$(auth_hdr)"
assert_status "200|201" "finding -> in_progress"

do_request POST /api/v1/findings/bulk/status \
  "{\"finding_ids\":[\"$FINDING_ID\"],\"status\":\"fix_applied\",\"resolution\":\"fix applied, awaiting validation\"}" \
  "$(auth_hdr)"
assert_status "200|201" "finding -> fix_applied (proof-of-fix state)"

# --- Producer: request validation ------------------------------------------
do_request POST "/api/v1/findings/$FINDING_ID/validate" "" "$(auth_hdr)"
assert_status "202" "POST /findings/{id}/validate returns 202"
assert_json '.command_id | length > 0' "validate returns a command_id"
COMMAND_ID="$(extract_json "$BODY" '.command_id')"
print_info "command_id=$COMMAND_ID"

# --- Agent side: create agent + drive the command lifecycle -----------------
do_request POST /api/v1/agents \
  "{\"name\":\"validate-runner-${TS}\",\"type\":\"runner\",\"capabilities\":[\"validate\"],\"execution_mode\":\"standalone\",\"max_concurrent_jobs\":1}" \
  "$(auth_hdr)"
assert_status "200|201" "create validation agent"
API_KEY="$(extract_json "$BODY" '.api_key')"

# Agent claims the queued validate command.
do_request POST "/api/v1/agent/commands/$COMMAND_ID/acknowledge" "" "X-API-Key: $API_KEY"
assert_status "200" "agent acknowledge command"
do_request POST "/api/v1/agent/commands/$COMMAND_ID/start" "" "X-API-Key: $API_KEY"
assert_status "200" "agent start command"

# Agent reports a safe-check outcome: the exposure is gone (not_detected).
do_request POST "/api/v1/agent/commands/$COMMAND_ID/complete" \
  "{\"result\":{\"outcome\":\"not_detected\",\"summary\":\"port closed; exposure no longer reachable\"}}" \
  "X-API-Key: $API_KEY"
assert_status "200" "agent complete command with outcome"

# --- Verify: evidence recorded + finding reconciled -------------------------
# The completion hook ingests evidence asynchronously; poll briefly.
EVIDENCE_OK=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  do_request GET "/api/v1/findings/$FINDING_ID/evidence" "" "$(auth_hdr)"
  if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | jq -e '.evidence | map(select(.outcome=="not_detected")) | length >= 1' >/dev/null 2>&1; then
    EVIDENCE_OK=1
    break
  fi
  sleep 0.5
done
if [ "$EVIDENCE_OK" = "1" ]; then
  print_success "validation evidence recorded (outcome=not_detected)"
else
  print_failure "validation evidence recorded" "no not_detected evidence for finding after 5s"
fi
assert_json '.evidence[0].executor_kind == "safe-check"' "evidence executor_kind is safe-check"

# Finding status reconciled to resolved (fix_applied -> resolved on not_detected).
do_request GET "/api/v1/findings/$FINDING_ID" "" "$(auth_hdr)"
assert_status "200" "get finding after validation"
assert_json '.status == "resolved"' "finding resolved by validation outcome"

# Validation coverage KPI reflects the validated finding.
do_request GET "/api/v1/validation/coverage" "" "$(auth_hdr)"
assert_status "200" "get validation coverage"
assert_json '.validated >= 1' "coverage counts at least one validated finding"
assert_json '.by_severity | map(select(.severity=="high")) | .[0].validated >= 1' "high-severity band shows the validated finding"

# Regression guard: a finding with MULTIPLE evidence rows must NOT inflate the
# per-severity total (total = distinct findings, not evidence rows). Dispatch a
# second validation for the same finding, then assert the high band still counts
# exactly one finding (this tenant has exactly one high finding).
do_request POST "/api/v1/findings/$FINDING_ID/validate" "" "$(auth_hdr)"
assert_status "202" "second validate dispatch"
COMMAND_ID2="$(extract_json "$BODY" '.command_id')"
do_request POST "/api/v1/agent/commands/$COMMAND_ID2/acknowledge" "" "X-API-Key: $API_KEY"
assert_status "200" "ack second command"
do_request POST "/api/v1/agent/commands/$COMMAND_ID2/start" "" "X-API-Key: $API_KEY"
assert_status "200" "start second command"
do_request POST "/api/v1/agent/commands/$COMMAND_ID2/complete" \
  "{\"result\":{\"outcome\":\"not_detected\",\"summary\":\"re-check 2\"}}" "X-API-Key: $API_KEY"
assert_status "200" "complete second command (2nd evidence row)"

# Poll until the second evidence row is ingested, then assert no inflation.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  do_request GET "/api/v1/findings/$FINDING_ID/evidence" "" "$(auth_hdr)"
  if echo "$BODY" | jq -e '.evidence | length >= 2' >/dev/null 2>&1; then break; fi
  sleep 0.5
done
assert_json '.evidence | length >= 2' "finding now has two evidence rows"
do_request GET "/api/v1/validation/coverage" "" "$(auth_hdr)"
assert_status "200" "get coverage after second evidence"
assert_json '.by_severity | map(select(.severity=="high")) | .[0].total == 1' "high total counts the finding once (not per-evidence)"

e2e_finish
