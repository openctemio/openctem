-- Revert to the original (buggy) function bodies from migration 000016:
-- recovery ignores p_max_retries and does not increment dispatch_attempts;
-- fail_exhausted only fails pending platform jobs.

CREATE OR REPLACE FUNCTION recover_stuck_tenant_commands(
    p_stuck_threshold_minutes INTEGER,
    p_max_retries INTEGER
) RETURNS INTEGER AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_commands AS (
        UPDATE commands
        SET agent_id = NULL,
            status = 'pending'
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fail_exhausted_commands(
    p_max_retries INTEGER
) RETURNS INTEGER AS $$
DECLARE
    failed_count INTEGER;
BEGIN
    WITH exhausted AS (
        UPDATE commands
        SET status = 'failed',
            error_message = 'Max dispatch attempts exceeded',
            completed_at = NOW()
        WHERE is_platform_job = TRUE
        AND status = 'pending'
        AND dispatch_attempts >= p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO failed_count FROM exhausted;

    RETURN failed_count;
END;
$$ LANGUAGE plpgsql;
