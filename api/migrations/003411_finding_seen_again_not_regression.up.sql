-- A finding the platform closed on its own (a covered scan did not report it,
-- nothing verified the fix) and that a scan reports again within days is
-- "seen again", not a regression: it reopens, but the regression counters and
-- the fresh SLA clock are for fixes that held and then failed.
--
-- finding_reopen_class says which a re-detected resolved finding is:
--   verified_regression  the close was verified (a retest or a review)
--   seen_again           an automatic close (no person), unverified, younger
--                        than the window (a flap)
--   regression           everything else
-- The scan reopen path puts the window (seconds) in its transition
-- (openctem.transition, seen_again_window_secs). Without it the window is 0
-- and no reopen is a flap, so every other writer behaves as before. The timeline trigger words the entry by class when the
-- transition names wording per class (reason_by_reopen_class,
-- message_by_reopen_class).

-- It takes the whole row (not its columns) so that a trigger naming it does not
-- depend on which columns an older schema has until it runs.
CREATE FUNCTION finding_reopen_class(r findings, p_window_secs double precision)
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN CASE
        WHEN COALESCE(r.verification, '') IN ('retest', 'security_review') THEN 'verified_regression'
        WHEN p_window_secs > 0 AND r.resolved_by IS NULL AND r.resolved_at > NOW() - make_interval(secs => p_window_secs) THEN 'seen_again'
        ELSE 'regression'
    END;
END;
$$;

CREATE FUNCTION finding_seen_again_window()
RETURNS double precision
LANGUAGE sql
STABLE PARALLEL SAFE
AS $$
    SELECT COALESCE(NULLIF(NULLIF(current_setting('openctem.transition', true), '')::jsonb->>'seen_again_window_secs', '')::double precision, 0)
$$;

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Closed dispositions (false_positive, accepted, duplicate) are triage
    -- corrections, not a fix that failed. A person's move (Undo) and a flap
    -- are reopens too, not regressions.
    IF OLD.status = 'resolved'
       AND NEW.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')
       AND COALESCE(current_setting('openctem.person_move', true), '') <> 'on'
       AND finding_reopen_class(OLD, finding_seen_again_window()) <> 'seen_again'
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION record_finding_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    ctx jsonb;
    prev jsonb;
    cls text;
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    END IF;
    ctx := NULLIF(current_setting('openctem.transition', true), '')::jsonb;
    IF ctx IS NULL THEN
        RETURN NULL;
    END IF;
    IF ctx ? 'reason_by_reopen_class' OR ctx ? 'message_by_reopen_class' THEN
        cls := finding_reopen_class(OLD, finding_seen_again_window());
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
                       'reason', COALESCE(ctx->'reason_by_reopen_class'->>cls, ctx->'reason_by_old_status'->>OLD.status, ctx->>'reason'),
                       'reopen_class', cls,
                       'closure_reason', NEW.closure_reason,
                       'verification', NEW.verification))
                || jsonb_build_object('old_status', OLD.status, 'new_status', NEW.status),
            COALESCE(ctx->>'source', 'auto'),
            COALESCE(ctx->'message_by_reopen_class'->>cls, ctx->>'message'));
    RETURN NULL;
END;
$$;
