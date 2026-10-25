ALTER TABLE findings DROP COLUMN IF EXISTS template_exposure;
UPDATE finding_retests SET reason_code = 'blocked' WHERE reason_code = 'edge_blocked';
UPDATE finding_retests SET reason_code = 'auth_changed' WHERE reason_code = 'access_denied';
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict'));
