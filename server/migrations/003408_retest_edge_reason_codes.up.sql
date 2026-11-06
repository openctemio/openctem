-- A retest answered by a CDN or WAF says so (edge_blocked), and an origin
-- 401 or 403 says access_denied. Widens the allowed reason codes; no data
-- changes.
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied'));

-- Whether the platform template that last matched the finding is of the
-- exposure class, from the template's own tags as the sensor reported them
-- (not the finding's editable tags). Nullable, no default: instant on a
-- populated table; a finding not sighted since stays NULL (not exposure).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS template_exposure boolean;
