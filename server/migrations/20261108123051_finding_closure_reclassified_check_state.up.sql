-- A compliance result stored as a finding before compliance check state
-- existed (a passed, not applicable or errored check) is moved to its
-- control's check state by the compliance-checks command
-- (docs/architecture/compliance-checks.md). It is resolved with the closure
-- reason reclassified_check_state and never counts as fixed (closure.go,
-- RemediatedSQL). Same rule table as before plus that one reason; a function
-- replacement: no table is rewritten or locked beyond the catalog.

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
                    'out_of_scope', 'reclassified_exposure', 'reclassified_check_state')
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
