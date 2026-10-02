-- Reverts 000260_command_leases.
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
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$function$;


DROP INDEX IF EXISTS idx_commands_lease_expiry;
ALTER TABLE commands DROP COLUMN IF EXISTS lease_expires_at;
ALTER TABLE commands DROP COLUMN IF EXISTS lease_epoch;
