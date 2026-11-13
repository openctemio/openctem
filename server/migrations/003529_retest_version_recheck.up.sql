-- Retest by provenance (docs/architecture/finding-retest-strategy.md): a
-- version-match finding is re-checked by re-running the fingerprint that read
-- the version and evaluating the version seen. The retest records its method
-- (tool, validate, version; older rows keep NULL and derive it from the check
-- command) and three new reason codes. No data changes; the constraints only
-- widen.
ALTER TABLE finding_retests ADD COLUMN IF NOT EXISTS method TEXT;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_method
    CHECK (method IS NULL OR method IN ('tool', 'validate', 'version'));
COMMENT ON COLUMN finding_retests.method IS
    'How the retest re-checked: tool (the tool''s retest handler), validate (template re-run and reachability probe), version (fingerprint re-run and version evaluation). NULL on rows from before migration 003450.';

ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied', 'matched_elsewhere', 'seen_after_check',
        'version_not_observed', 'version_still_affected', 'version_not_affected'));
