-- Keeps closure_reason / verification consistent for every writer, adds the
-- CHECK (NOT VALID; validated in finding_closure_validate) and records the
-- previous closure on the timeline (closure.go).

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


-- A row closed between the backfill and this trigger (none while the API is
-- stopped for the upgrade) gets its status default now, so VALIDATE passes.
UPDATE findings SET closure_reason = closure_reason
WHERE status IN ('resolved', 'false_positive', 'accepted', 'duplicate') AND closure_reason IS NULL;
