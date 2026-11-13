UPDATE finding_retests SET reason_code = 'error'
 WHERE reason_code IN ('template_not_found', 'excluded_by_policy', 'no_verdict');
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated'));
