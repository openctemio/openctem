-- Findings closed as out_of_scope go back to the reason the old rule table
-- accepts for a platform closure without a fix (obsolete_asset), so the
-- restored function never sees a value it refuses.
UPDATE findings SET closure_reason = 'obsolete_asset', updated_at = NOW()
WHERE closure_reason = 'out_of_scope';

CREATE OR REPLACE FUNCTION finding_closure_valid(p_status text, p_reason text, p_verification text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT COALESCE(CASE
        WHEN p_status IN ('resolved', 'false_positive', 'accepted', 'duplicate') THEN
            p_reason IS NOT NULL
            AND (p_reason = 'unknown' OR CASE p_status
                WHEN 'resolved' THEN p_reason IN ('fixed', 'mitigated', 'obsolete_asset', 'obsolete_source', 'obsolete_rule')
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

ALTER TABLE scope_exclusions DROP CONSTRAINT IF EXISTS chk_scope_exclusions_kind;
ALTER TABLE scope_exclusions DROP COLUMN IF EXISTS kind;
