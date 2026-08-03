-- Restore the original single-argument recover_stuck_platform_jobs from
-- 000016_agents.up.sql, replacing the delegating wrapper. Note that the restored
-- version can never match a row.

DROP FUNCTION IF EXISTS recover_stuck_platform_jobs(INTEGER, INTEGER);
DROP FUNCTION IF EXISTS recover_stuck_platform_jobs(INTEGER);

CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(
    p_stuck_threshold_minutes INTEGER
) RETURNS INTEGER AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET platform_agent_id = NULL,
            status = 'pending',
            dispatch_attempts = dispatch_attempts
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        AND platform_agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < 3
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;
