-- Command leases (RFC-035 decision D6, docs/rfcs/RFC-035-sensor-control-plane-under-load.md
-- §5.7; RFC-030 D6): a sensor holds a claimed command under a lease it
-- renews while it is alive (every heartbeat that lists the command, and
-- start). A lease that runs out means the sensor died or lost the command:
-- the job-recovery controller puts it back to pending at once instead of
-- waiting for the run timeout.
--
-- lease_epoch counts the claims of a command. Every sensor-side state change
-- (start, complete, fail) is a guarded UPDATE that must still see the sensor,
-- the state and the epoch it read, so a sensor whose command was re-queued
-- (and maybe claimed again) can never complete it: no duplicate completion.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS lease_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_commands_lease_expiry
    ON commands (lease_expires_at)
    WHERE status IN ('acknowledged', 'running') AND lease_expires_at IS NOT NULL;

-- The time-based reaper (acknowledged for 10 minutes) now leaves leased
-- commands to the lease: a sensor that is alive and renewing keeps its work.
CREATE OR REPLACE FUNCTION recover_stuck_tenant_commands(p_stuck_threshold_minutes integer, p_max_retries integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_commands AS (
        UPDATE commands
        SET sensor_id = NULL,
            status = 'pending',
            -- Tenant commands have no other dispatch-attempt accounting, so
            -- count each recovery as an attempt. This gives the max_retries
            -- guard a stopping condition and lets fail_exhausted_commands take
            -- over once the command is exhausted.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND sensor_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        AND lease_expires_at IS NULL
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$function$;

