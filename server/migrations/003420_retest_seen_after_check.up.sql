-- A retest whose check ran before a scan sighted the finding again is
-- inconclusive with reason seen_after_check (the check no longer shows the
-- current state). Widens the reason check constraint only; no data changes.
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied', 'matched_elsewhere', 'seen_after_check'));
