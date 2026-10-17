-- Restores the timeline function that recorded resolution_method (the
-- column is back after finding_closure_drop_resolution_method down).
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
        'previous_resolution_method', OLD.resolution_method,
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
                       'reason', COALESCE(ctx->'reason_by_old_status'->>OLD.status, ctx->>'reason')))
                || jsonb_build_object('old_status', OLD.status, 'new_status', NEW.status),
            COALESCE(ctx->>'source', 'auto'),
            ctx->>'message');
    RETURN NULL;
END;
$$;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_closure;
DROP TRIGGER IF EXISTS trg_findings_settle_closure ON findings;
DROP FUNCTION IF EXISTS findings_closure_defaults();
