ALTER TABLE findings ADD COLUMN resolution_method varchar(30);

UPDATE findings SET resolution_method = CASE
        WHEN verification = 'covered_scan' THEN 'scan_verified'
        WHEN verification = 'retest' THEN 'retest_verified'
        WHEN verification = 'security_review' AND status = 'resolved' THEN 'security_reviewed'
        WHEN verification = 'attested' THEN 'admin_direct'
        WHEN verification = 'vex_statement' AND status = 'resolved' THEN 'vex_fixed'
        WHEN verification = 'vex_statement' THEN 'vex_not_affected'
        WHEN closure_reason = 'obsolete_source' THEN 'source_retired'
        WHEN closure_reason = 'obsolete_rule' THEN 'license_policy'
        WHEN closure_reason = 'detection_error' AND verification = 'source_reported' THEN 'advisory_updated'
        WHEN verification = 'source_reported' AND status = 'resolved' THEN 'source_mitigated'
    END
WHERE closure_reason IS NOT NULL;

