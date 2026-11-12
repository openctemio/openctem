UPDATE finding_retests SET reason_code = 'no_endpoint_proof' WHERE reason_code = 'check_uncalibrated';
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error'));
ALTER TABLE finding_retests
    DROP COLUMN IF EXISTS check_path,
    DROP COLUMN IF EXISTS check_digest,
    DROP COLUMN IF EXISTS retest_check_id;
DROP TABLE IF EXISTS finding_retest_checks;
DROP INDEX IF EXISTS ux_scanner_templates_id_tenant;
