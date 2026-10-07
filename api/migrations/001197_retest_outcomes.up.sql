-- Retest outcomes that say what a retest proved (RFC-057 R2). A check that
-- did not match is no longer, by itself, a fix:
--   confirmed_fixed   the endpoint answered and the check did not match
--   not_reproduced    no match, but the endpoint was not proven to be checked
--   still_vulnerable  the check matched again
--   inconclusive      no conclusion; reason_code says why
-- Earlier rows: fixed (a non-match with no endpoint proof) reads
-- not_reproduced, still_present still_vulnerable, unknown inconclusive. No
-- finding status changes here.

ALTER TABLE finding_retests ADD COLUMN reason_code varchar(32);

ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_outcome;

UPDATE finding_retests SET
    outcome = CASE outcome
        WHEN 'fixed' THEN 'not_reproduced'
        WHEN 'still_present' THEN 'still_vulnerable'
        WHEN 'unknown' THEN 'inconclusive'
        ELSE outcome END,
    reason_code = CASE outcome
        WHEN 'fixed' THEN 'no_endpoint_proof'
        WHEN 'still_present' THEN 'matched'
        WHEN 'unknown' THEN 'no_result'
        END
WHERE outcome IS NOT NULL;

ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_outcome CHECK (
    outcome IS NULL OR outcome IN ('confirmed_fixed', 'not_reproduced', 'still_vulnerable', 'inconclusive'));
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error'));
