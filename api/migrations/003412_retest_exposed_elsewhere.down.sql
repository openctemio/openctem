UPDATE finding_retests SET outcome = 'inconclusive', reason_code = 'endpoint_mismatch'
 WHERE outcome = 'still_exposed_elsewhere';
UPDATE finding_retests SET reason_code = 'endpoint_mismatch' WHERE reason_code = 'matched_elsewhere';
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied'));
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_outcome;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_outcome CHECK (
    outcome IS NULL OR outcome IN ('confirmed_fixed', 'not_reproduced', 'still_vulnerable', 'inconclusive'));
ALTER TABLE finding_retests ALTER COLUMN outcome TYPE varchar(16);
