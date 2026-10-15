-- Why a closed finding is closed and how a closing claim was proven
-- (pkg/domain/vulnerability/closure.go), replacing resolution_method.
--
--   closure_reason  required on a closed finding, NULL on an open one; a closed
--                   set per status, aligned with the VEX justifications.
--   verification    how a resolve (or a platform false positive) was proven.
--
-- Backfill is conservative: a resolution_method that names its evidence maps
-- to it; everything else becomes 'unknown', never a guessed reason.
-- A BEFORE trigger keeps the pair consistent for every writer: it clears both
-- on an open status, drops a value left over from the previous status that
-- does not fit the new one, and fills
-- the status default ('unknown', 'duplicate') when a writer names none. The CHECK is added NOT VALID here and validated in the next
-- migration.

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

-- Backfill closed rows from resolution_method (live: 13 closed rows).
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
WHERE status IN ('resolved', 'false_positive', 'accepted', 'duplicate');

CREATE OR REPLACE FUNCTION findings_closure_defaults()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate') THEN
        NEW.closure_reason := NULL;
        NEW.verification := NULL;
        RETURN NEW;
    END IF;
    -- A reason or verification left over from the previous status (a writer
    -- that moved the status without naming a new one) is dropped when it does
    -- not fit the new status. A value the writer set itself is kept, so a
    -- wrong one fails the CHECK instead of being hidden.
    IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
        IF NEW.closure_reason IS NOT DISTINCT FROM OLD.closure_reason
           AND NOT finding_closure_valid(NEW.status, NEW.closure_reason,
                                         CASE WHEN NEW.status = 'resolved' THEN 'unknown' END) THEN
            NEW.closure_reason := NULL;
        END IF;
        IF NEW.verification IS NOT DISTINCT FROM OLD.verification
           AND NOT finding_closure_valid(NEW.status, 'unknown', NEW.verification) THEN
            NEW.verification := NULL;
        END IF;
    END IF;
    IF NEW.closure_reason IS NULL THEN
        NEW.closure_reason := CASE WHEN NEW.status = 'duplicate' THEN 'duplicate' ELSE 'unknown' END;
    END IF;
    IF NEW.status = 'resolved' AND NEW.verification IS NULL THEN
        NEW.verification := CASE WHEN NEW.closure_reason LIKE 'obsolete\_%' THEN 'none' ELSE 'unknown' END;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION findings_closure_defaults() IS
    'Keeps closure_reason / verification consistent with the status for every writer (closure.go)';

-- On every insert and update, not only those naming status: another BEFORE
-- trigger may change the status (trg_findings_reopen_orphaned_duplicate reopens
-- a duplicate whose canonical finding was deleted). BEFORE triggers fire in
-- name order, so this one is named to run after every trigger that changes
-- the status ("settle" sorts after "reopen" and "recompute").
CREATE TRIGGER trg_findings_settle_closure
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION findings_closure_defaults();

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_closure
    CHECK (finding_closure_valid(status::text, closure_reason::text, verification::text)) NOT VALID;

-- A false positive or accepted-risk request names its reason; the approval
-- applies it.
ALTER TABLE finding_status_approvals ADD COLUMN closure_reason varchar(64);
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_closure
    CHECK (closure_reason IS NULL
           OR finding_closure_valid(requested_status, closure_reason::text, NULL));

-- The timeline trigger records the previous closure instead of the method.
CREATE OR REPLACE FUNCTION record_finding_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    ctx jsonb;
    prev jsonb;
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    END IF;
    ctx := NULLIF(current_setting('openctem.transition', true), '')::jsonb;
    IF ctx IS NULL THEN
        RETURN NULL;
    END IF;
    prev := jsonb_strip_nulls(jsonb_build_object(
        'previous_resolution', OLD.resolution,
        'previous_closure_reason', OLD.closure_reason,
        'previous_verification', OLD.verification,
        'previous_resolved_by', OLD.resolved_by,
        'previous_resolved_at', OLD.resolved_at));
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, actor_name,
                                    changes, source, message)
    VALUES (NEW.tenant_id, NEW.id,
            COALESCE(ctx->>'activity_type', 'status_changed'),
            COALESCE(ctx->>'actor_type', 'system'),
            NULLIF(ctx->>'actor_id', '')::uuid,
            ctx->>'actor_name',
            COALESCE(ctx->'changes', '{}'::jsonb)
                || prev
                || jsonb_strip_nulls(jsonb_build_object(
                       'reason', COALESCE(ctx->'reason_by_old_status'->>OLD.status, ctx->>'reason'),
                       'closure_reason', NEW.closure_reason,
                       'verification', NEW.verification))
                || jsonb_build_object('old_status', OLD.status, 'new_status', NEW.status),
            COALESCE(ctx->>'source', 'auto'),
            ctx->>'message');
    RETURN NULL;
END;
$$;

ALTER TABLE findings DROP COLUMN resolution_method;
