-- Backfills closure_reason / verification on closed findings from what
-- resolution_method recorded; everything else becomes 'unknown', never a
-- guessed reason (closure.go). Runs before the trigger exists, in batches of
-- 1000 rows, each committed on its own (a single DO statement outside a
-- transaction block), so no lock on findings is held across the table.
DO $$
DECLARE
    moved integer;
BEGIN
    LOOP
        UPDATE findings SET
            closure_reason = CASE status
                WHEN 'resolved' THEN CASE resolution_method
                    WHEN 'scan_verified' THEN 'fixed'
                    WHEN 'retest_verified' THEN 'fixed'
                    WHEN 'security_reviewed' THEN 'fixed'
                    WHEN 'admin_direct' THEN 'fixed'
                    WHEN 'source_mitigated' THEN 'fixed'
                    WHEN 'vex_fixed' THEN 'fixed'
                    WHEN 'version_changed' THEN 'fixed'
                    WHEN 'source_retired' THEN 'obsolete_source'
                    WHEN 'license_policy' THEN 'obsolete_rule'
                    ELSE 'unknown' END
                WHEN 'false_positive' THEN CASE
                    WHEN resolution_method = 'vex_not_affected'
                         AND vex_justification IN ('component_not_present', 'vulnerable_code_not_present',
                             'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
                             'inline_mitigations_already_exist') THEN vex_justification
                    WHEN resolution_method = 'advisory_updated' THEN 'detection_error'
                    ELSE 'unknown' END
                WHEN 'accepted' THEN 'unknown'
                ELSE CASE WHEN resolution = 'correlated' THEN 'correlated' ELSE 'duplicate' END
            END,
            verification = CASE status
                WHEN 'resolved' THEN CASE resolution_method
                    WHEN 'scan_verified' THEN 'covered_scan'
                    WHEN 'retest_verified' THEN 'retest'
                    WHEN 'security_reviewed' THEN 'security_review'
                    WHEN 'admin_direct' THEN 'attested'
                    WHEN 'source_mitigated' THEN 'source_reported'
                    WHEN 'version_changed' THEN 'source_reported'
                    WHEN 'vex_fixed' THEN 'vex_statement'
                    WHEN 'source_retired' THEN 'none'
                    WHEN 'license_policy' THEN 'none'
                    ELSE 'unknown' END
                WHEN 'false_positive' THEN CASE resolution_method
                    WHEN 'vex_not_affected' THEN 'vex_statement'
                    WHEN 'advisory_updated' THEN 'source_reported'
                    ELSE NULL END
                ELSE NULL
            END
        WHERE id IN (
                    SELECT id FROM findings
                    WHERE status IN ('resolved', 'false_positive', 'accepted', 'duplicate') AND closure_reason IS NULL
                    LIMIT 1000);
        GET DIAGNOSTICS moved = ROW_COUNT;
        EXIT WHEN moved = 0;
        COMMIT;
    END LOOP;
END
$$;
