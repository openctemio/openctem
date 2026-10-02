-- Platform job recovery lifecycle fix.
--
-- recover_stuck_platform_jobs could never match a single row, so the
-- job-recovery controller logged "recovered stuck platform jobs: 0" forever and
-- read as healthy while doing nothing. Two independent reasons:
--
--   1. It required `platform_agent_id IS NOT NULL`. Nothing sets that column.
--      The only writer is get_next_platform_job, which has no Go caller
--      (CommandRepository.GetNextPlatformJob is dead code); Command.
--      AssignToPlatformAgent has no callers either. In practice a platform job
--      is claimed by an ordinary *tenant* agent through the normal
--      GET /api/v1/agent/commands poll — GetPendingForAgent and ClaimForAgent
--      do not filter on is_platform_job, and platform jobs are created with
--      agent_id NULL, so every tenant agent sees them. ClaimForAgent sets
--      agent_id, not platform_agent_id.
--
--   2. It ignored the caller's max-retries setting: the Go wrapper binds only
--      the threshold and the SQL hardcoded `dispatch_attempts < 3`. Harmless
--      only for as long as the configured value stays 3.
--
-- The gap this leaves is not cosmetic. A platform job acknowledged by a tenant
-- agent that then dies is stuck in 'acknowledged' permanently:
--   * recover_stuck_platform_jobs skips it   (platform_agent_id IS NULL)
--   * recover_stuck_tenant_commands skips it (is_platform_job = FALSE, 000172)
--   * ExpireOldPlatformJobs skips it         (status = 'pending' only)
--   * fail_exhausted_commands skips it       (dispatch_attempts never leaves 0,
--                                             because only the two recovery
--                                             functions increment it)
-- and the owning pipeline run waits on it forever.
--
-- Fix, mirroring what 000172 did for tenant commands: match the state that
-- actually occurs (acknowledged, claimed by either kind of agent), honour
-- p_max_retries, and increment dispatch_attempts so fail_exhausted_commands
-- has a stopping condition to take over from.

CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(
    p_stuck_threshold_minutes INTEGER,
    p_max_retries INTEGER
) RETURNS INTEGER AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET platform_agent_id = NULL,
            agent_id = NULL,
            status = 'pending',
            -- Clearing acknowledged_at keeps the row honest once it is back in
            -- the queue; ClaimForAgent sets it again on the next claim.
            acknowledged_at = NULL,
            -- Count each recovery as a dispatch attempt. Without this the
            -- counter never moves for a platform job and fail_exhausted_commands
            -- (dispatch_attempts >= p_max_retries) can never take over.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        -- Claimed by *either* dispatch path: platform_agent_id is what
        -- get_next_platform_job would set, agent_id is what the poll path
        -- actually sets today.
        AND (platform_agent_id IS NOT NULL OR agent_id IS NOT NULL)
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;

-- Keep the single-argument signature as a delegating wrapper instead of
-- dropping it. During a rolling deploy the old pods still call
-- recover_stuck_platform_jobs($1) every 60s; dropping it would make that call
-- error until the last old pod is replaced. The wrapper also means those pods
-- get the corrected WHERE clause for free. It carries the retry limit the old
-- SQL hardcoded, so its behaviour is unchanged for them.
CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(
    p_stuck_threshold_minutes INTEGER
) RETURNS INTEGER AS $$
    SELECT recover_stuck_platform_jobs(p_stuck_threshold_minutes, 3);
$$ LANGUAGE sql;
