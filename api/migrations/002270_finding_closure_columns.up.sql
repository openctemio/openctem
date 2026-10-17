-- Why a closed finding is closed and how a closing claim was proven
-- (pkg/domain/vulnerability/closure.go), replacing resolution_method. Five
-- steps, so no step holds a lock on findings longer than it must:
--   finding_closure_columns (this): the columns, the rule function, the
--     approvals column. Adding nullable columns is a catalog change.
--   finding_closure_backfill: the closed rows, in batches.
--   finding_closure_trigger: the trigger and the CHECK (NOT VALID).
--   finding_closure_validate: VALIDATE.
--   finding_closure_drop_resolution_method: drop the replaced column.

ALTER TABLE findings
    ADD COLUMN closure_reason varchar(64),
    ADD COLUMN verification   varchar(32);

COMMENT ON COLUMN findings.closure_reason IS
    'Why a closed finding is closed (closure.go ClosureReason); NULL while open';
COMMENT ON COLUMN findings.verification IS
    'How a resolve or a platform false positive was proven (closure.go Verification)';

-- finding_closure_valid is the one SQL statement of closure.go: which reasons
-- and verifications each status accepts. A DB test pins it to the Go tables.
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

COMMENT ON FUNCTION finding_closure_valid(text, text, text) IS
    'Whether a finding status accepts this closure reason and verification (closure.go)';

-- A false positive or accepted-risk request names its reason; the approval
-- applies it.
ALTER TABLE finding_status_approvals ADD COLUMN closure_reason varchar(64);
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_closure
    CHECK (closure_reason IS NULL
           OR finding_closure_valid(requested_status, closure_reason::text, NULL));

