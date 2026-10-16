-- The shared claim path (docs/rfcs/RFC-100-shared-sensors.md §8, RFC-090
-- W11/W12). A shared sensor claims shared jobs (is_platform_job) through the
-- API's claim; the holder of a shared job is commands.sensor_id, like every
-- other job, so leases, lease epochs, fencing, re-queue on expiry and result
-- binding are the same for both.
--
--   1. sensors.accepts_unzoned_jobs: a shared sensor takes unzoned public
--      jobs (the default) or none (a sensor kept for zone work only).
--   2. get_next_platform_job is removed: it never had a caller.
--   3. commands.platform_sensor_id is removed: only that function ever set
--      it. record_command_event and recover_stuck_platform_jobs stop reading
--      it first.
--
-- Live impact: a column with a constant default on sensors (one row per
-- sensor, no rewrite); a dropped nullable column and its index on commands
-- (catalog only, a brief exclusive lock).

SET LOCAL lock_timeout = '5s';

ALTER TABLE sensors ADD COLUMN IF NOT EXISTS accepts_unzoned_jobs boolean NOT NULL DEFAULT TRUE;
COMMENT ON COLUMN sensors.accepts_unzoned_jobs IS
    'A shared sensor (scope instance) takes unzoned shared jobs only when true. Ignored for organization sensors.';

DROP FUNCTION IF EXISTS get_next_platform_job(uuid, text[], text[]);

CREATE OR REPLACE FUNCTION record_command_event() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ev      TEXT;
    sensor  UUID := NEW.sensor_id;
    msg     TEXT;
    code    TEXT;
    run     UUID;
    refusal JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        ev := 'queued';
    ELSIF jsonb_array_length(COALESCE(NEW.refusals, '[]')) > jsonb_array_length(COALESCE(OLD.refusals, '[]')) THEN
        ev := 'refused';
        refusal := NEW.refusals -> -1;
        sensor := COALESCE(OLD.sensor_id, NULLIF(refusal ->> 'sensor_id', '')::uuid);
        code := left(concat_ws('.', refusal ->> 'layer', refusal ->> 'rule'), 100);
        msg := refusal ->> 'detail';
    ELSIF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    ELSIF NEW.status = 'pending' THEN
        ev := 'requeued';
        sensor := OLD.sensor_id;
        msg := NEW.error_message;
    ELSIF NEW.status = 'acknowledged' THEN
        ev := 'claimed';
    ELSIF NEW.status = 'running' THEN
        ev := 'started';
    ELSIF NEW.status IN ('completed', 'failed', 'canceled', 'expired') THEN
        ev := NEW.status;
        IF NEW.status <> 'completed' THEN
            msg := NEW.error_message;
        END IF;
    ELSE
        ev := 'changed';
    END IF;

    BEGIN
        run := NULLIF(NEW.payload ->> 'scan_run_id', '')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        run := NULL;
    END;

    INSERT INTO command_events (tenant_id, command_id, run_id, event, status, attempt, platform, sensor_id, code, message)
    VALUES (NEW.tenant_id, NEW.id, run, ev, NEW.status, COALESCE(NEW.dispatch_attempts, 0),
            COALESCE(NEW.is_platform_job, false), sensor, code, left(msg, 2000));
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(p_stuck_threshold_minutes integer, p_max_retries integer) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET sensor_id = NULL,
            status = 'pending',
            acknowledged_at = NULL,
            lease_expires_at = NULL,
            -- Count each recovery as a dispatch attempt so
            -- fail_exhausted_commands can end a job that keeps getting stuck.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        AND sensor_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$$;

ALTER TABLE commands DROP COLUMN IF EXISTS platform_sensor_id;
