-- Tenant command retry lifecycle fix.
--
-- Two pre-existing bugs let a stuck tenant command (assigned to an agent that
-- then went offline) loop forever and never fail:
--
--   1. recover_stuck_tenant_commands took a p_max_retries parameter but never
--      used it, and never incremented dispatch_attempts. Tenant commands don't
--      increment dispatch_attempts anywhere else in their lifecycle (unlike
--      platform jobs, which increment on claim/assign), so the attempt counter
--      stayed at 0 and recovery had no stopping condition.
--
--   2. fail_exhausted_commands only failed platform jobs (is_platform_job=TRUE),
--      so an exhausted tenant command was never marked failed. The same gap
--      left exhausted *acknowledged* commands (tenant or platform) stuck,
--      because the function only looked at status='pending'.
--
-- Fix: recovery now increments dispatch_attempts and stops once it reaches
-- p_max_retries; fail_exhausted now fails exhausted commands regardless of
-- is_platform_job and covers both 'pending' and 'acknowledged' states.

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
            status = 'pending',
            -- Tenant commands have no other dispatch-attempt accounting, so
            -- count each recovery as an attempt. This gives the max_retries
            -- guard a stopping condition and lets fail_exhausted_commands take
            -- over once the command is exhausted.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
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
        -- Cover both platform and tenant commands, and both queued ('pending')
        -- and claimed-but-stuck ('acknowledged') states. A command that has
        -- exhausted its dispatch attempts is dead regardless of who owns it.
        WHERE status IN ('pending', 'acknowledged')
        AND dispatch_attempts >= p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO failed_count FROM exhausted;

    RETURN failed_count;
END;
$$ LANGUAGE plpgsql;
