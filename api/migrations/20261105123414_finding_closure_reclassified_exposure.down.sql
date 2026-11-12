-- Findings moved to exposures go back to the reason the old rule table
-- accepts for a platform closure without a fix (obsolete_rule: the check
-- changed), so the restored function never sees a value it refuses; they
-- stay resolved and still never count as fixed. Sub-statuses bound to the
-- reason follow (their category guard allows no change, so none may exist:
-- the down refuses to run while one does).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM lifecycle_sub_statuses WHERE closure_reason = 'reclassified_exposure') THEN
        RAISE EXCEPTION 'a sub-status is bound to reclassified_exposure; archive and remove it before rolling back';
    END IF;
END
$$;

UPDATE findings SET closure_reason = 'obsolete_rule', updated_at = NOW()
WHERE closure_reason = 'reclassified_exposure';

CREATE OR REPLACE FUNCTION finding_closure_valid(p_status text, p_reason text, p_verification text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT COALESCE(CASE
        WHEN p_status IN ('resolved', 'false_positive', 'accepted', 'duplicate') THEN
            p_reason IS NOT NULL
            AND (p_reason = 'unknown' OR CASE p_status
                WHEN 'resolved' THEN p_reason IN ('fixed', 'mitigated', 'obsolete_asset', 'obsolete_source', 'obsolete_rule',
                    'out_of_scope')
                WHEN 'false_positive' THEN p_reason IN ('component_not_present', 'vulnerable_code_not_present',
                    'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
                    'inline_mitigations_already_exist', 'detection_error', 'test_or_example_code')
                WHEN 'accepted' THEN p_reason IN ('risk_accepted', 'compensating_control', 'wont_fix', 'no_fix_available')
                ELSE p_reason IN ('duplicate', 'correlated')
            END)
            AND CASE p_status
                WHEN 'resolved' THEN p_verification IN ('covered_scan', 'retest', 'source_reported', 'vex_statement',
                    'security_review', 'attested', 'none', 'unknown')
                WHEN 'false_positive' THEN p_verification IS NULL
                    OR p_verification IN ('source_reported', 'vex_statement', 'security_review', 'unknown')
                ELSE p_verification IS NULL
            END
        ELSE p_reason IS NULL AND p_verification IS NULL
    END, false)
$$;
