-- The version reason codes have no older equivalent: version_not_observed
-- becomes no_result, the two conclusive ones become matched / not_matched.
UPDATE finding_retests SET reason_code = 'no_result' WHERE reason_code = 'version_not_observed';
UPDATE finding_retests SET reason_code = 'matched' WHERE reason_code = 'version_still_affected';
UPDATE finding_retests SET reason_code = 'not_matched' WHERE reason_code = 'version_not_affected';
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied', 'matched_elsewhere', 'seen_after_check'));

ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS chk_finding_retests_method;
ALTER TABLE finding_retests DROP COLUMN IF EXISTS method;
