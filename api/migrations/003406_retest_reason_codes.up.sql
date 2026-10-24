-- A retest the tool could not run now says why: its template is not on the
-- sensor (template_not_found), the sensor's safety policy never runs it
-- (excluded_by_policy), or the tool ended without judging the item
-- (no_verdict). Widens the allowed reason codes; no data changes.
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict'));
